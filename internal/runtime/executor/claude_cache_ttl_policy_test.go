package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// Gateway policy: a cloaked OAuth request only joins the 1h cache pool when the
// caller asked for it. A bare {"type":"ephemeral"} (the API's 5m default), an
// explicit "5m", or no marker at all must reach Anthropic without any 1h ttl and
// without extended-cache-ttl, on both Execute and ExecuteStream. A 1h write costs
// 2x base input versus 1.25x for 5m, and agent loops never idle long enough for
// 1h to pay off.
func TestClaudeExecutor_CloakedOAuthCacheTTLFollowsCaller(t *testing.T) {
	cases := []struct {
		name     string
		systemCC string
		userCC   string
		want1h   bool
		// laterCC, when set, appends an assistant turn and a later user turn
		// carrying this marker; wantLaterTTL is the ttl that turn must reach
		// upstream with ("" is the 5m default).
		laterCC      string
		wantLaterTTL string
	}{
		{name: "bare system marker", systemCC: `,"cache_control":{"type":"ephemeral"}`},
		{name: "explicit 5m system marker", systemCC: `,"cache_control":{"type":"ephemeral","ttl":"5m"}`},
		{name: "no caller markers"},
		{name: "explicit 1h system marker", systemCC: `,"cache_control":{"type":"ephemeral","ttl":"1h"}`, want1h: true},
		{
			name:     "1h system then 5m user marker",
			systemCC: `,"cache_control":{"type":"ephemeral","ttl":"1h"}`,
			userCC:   `,"cache_control":{"type":"ephemeral","ttl":"5m"}`,
			want1h:   true,
		},
		{
			name:     "1h system keeps a later bare marker in the 5m pool",
			systemCC: `,"cache_control":{"type":"ephemeral","ttl":"1h"}`,
			laterCC:  `,"cache_control":{"type":"ephemeral"}`,
			want1h:   true,
		},
		{
			name:     "1h system keeps an unmarked later turn in the 5m pool",
			systemCC: `,"cache_control":{"type":"ephemeral","ttl":"1h"}`,
			laterCC:  " ",
			want1h:   true,
		},
		{
			name:         "1h on the later turn covers the whole prefix",
			systemCC:     `,"cache_control":{"type":"ephemeral"}`,
			laterCC:      `,"cache_control":{"type":"ephemeral","ttl":"1h"}`,
			want1h:       true,
			wantLaterTTL: "1h",
		},
	}
	for _, tc := range cases {
		for _, stream := range []bool{false, true} {
			name := tc.name + "/execute"
			if stream {
				name = tc.name + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				var mu sync.Mutex
				var seenBody []byte
				var seenHeaders http.Header
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					mu.Lock()
					seenBody, seenHeaders = body, r.Header.Clone()
					mu.Unlock()
					if stream {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-4-6\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
				}))
				defer server.Close()

				executor := NewClaudeExecutor(&config.Config{})
				auth := &cliproxyauth.Auth{
					ID: "cache-ttl-follows-caller",
					Attributes: map[string]string{
						"api_key":    "sk-ant-oat-cache-ttl-follows-caller",
						"base_url":   server.URL,
						"cloak_mode": "always",
					},
					Metadata: claudeOAuthTestMetadata(),
				}
				laterTurn := ""
				if tc.laterCC != "" {
					laterTurn = `,{"role":"assistant","content":"ok"},{"role":"user","content":[{"type":"text","text":"later"` + strings.TrimSpace(tc.laterCC) + `}]}`
				}
				payload := []byte(`{"model":"claude-opus-4-6","max_tokens":64,` +
					`"system":[{"type":"text","text":"caller system prompt"` + tc.systemCC + `}],` +
					`"messages":[{"role":"user","content":[{"type":"text","text":"hi"` + tc.userCC + `}]}` + laterTurn + `]}`)
				req := cliproxyexecutor.Request{Model: "claude-opus-4-6", Payload: payload}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, OriginalRequest: payload}
				if stream {
					result, err := executor.ExecuteStream(context.Background(), auth, req, opts)
					if err != nil {
						t.Fatalf("ExecuteStream() error = %v", err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatalf("stream chunk error: %v", chunk.Err)
						}
					}
				} else if _, err := executor.Execute(context.Background(), auth, req, opts); err != nil {
					t.Fatalf("Execute() error = %v", err)
				}

				mu.Lock()
				defer mu.Unlock()
				if len(seenBody) == 0 {
					t.Fatal("upstream request was not captured")
				}
				if got := gjson.GetBytes(seenBody, "system.1.cache_control.type").String(); got != "ephemeral" {
					t.Fatalf("cloaked identity block lost its breakpoint: %s", seenBody)
				}
				if got := helps.ClaudePayloadHas1hTTL(seenBody); got != tc.want1h {
					t.Fatalf("upstream body has 1h ttl = %v, want %v: %s", got, tc.want1h, seenBody)
				}
				gotBeta := strings.Contains(seenHeaders.Get("Anthropic-Beta"), claudeExtendedCacheTTLBeta)
				if gotBeta != tc.want1h {
					t.Fatalf("extended-cache-ttl declared = %v, want %v: %s", gotBeta, tc.want1h, seenHeaders.Get("Anthropic-Beta"))
				}
				if tc.laterCC != "" {
					later := gjson.GetBytes(seenBody, "messages.#(content.#(text==\"later\")).content.#(text==\"later\")")
					if got := later.Get("cache_control.type").String(); got != "ephemeral" {
						t.Fatalf("later user turn has no breakpoint: %s", seenBody)
					}
					if got := later.Get("cache_control.ttl").String(); got != tc.wantLaterTTL {
						t.Fatalf("later user turn ttl = %q, want %q: %s", got, tc.wantLaterTTL, seenBody)
					}
				}
				// Anthropic rejects a 1h breakpoint that follows a 5m one.
				seen5m := false
				forEachClaudeCacheControlBlock(seenBody, func(path string, block gjson.Result) {
					cc := block.Get("cache_control")
					if !cc.Exists() {
						return
					}
					if cc.Get("ttl").String() == "1h" {
						if seen5m {
							t.Fatalf("1h breakpoint at %s follows a 5m breakpoint: %s", path, seenBody)
						}
						return
					}
					seen5m = true
				})
			})
		}
	}
}
