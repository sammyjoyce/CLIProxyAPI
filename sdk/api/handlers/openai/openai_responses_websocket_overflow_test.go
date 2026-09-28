package openai

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/tidwall/gjson"
)

type websocketPipeliningExecutor struct {
	homeResponsesWebsocketExecutor
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (e *websocketPipeliningExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	call := e.calls.Add(1)
	chunks := make(chan coreexecutor.StreamChunk, 1)
	go func() {
		defer close(chunks)
		if call == 1 {
			close(e.started)
			select {
			case <-ctx.Done():
				return
			case <-e.release:
			}
		}
		chunks <- coreexecutor.StreamChunk{Payload: []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"overflow-%d","output":[]}}`, call))}
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

type websocketClientRead struct {
	messageType int
	payload     []byte
	err         error
}

// TestResponsesWebsocketPipeliningBackpressure pins the reader goroutine's
// queue behavior: one in-flight request plus one buffered message, and further
// pipelined messages apply TCP backpressure instead of failing the session
// with a 429 (the pre-hardening upstream behavior clients are built against).
func TestResponsesWebsocketPipeliningBackpressure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name       string
		queued     int
		disconnect bool
	}{
		{name: "one pending request keeps session reusable", queued: 1},
		{name: "deep pipelining backpressures instead of failing", queued: 3},
		{name: "disconnect during pipelined backpressure stops queued work", queued: 3, disconnect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := &websocketPipeliningExecutor{started: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(executor.release) })
			t.Cleanup(release)
			manager := coreauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(executor)
			auth := &coreauth.Auth{ID: t.Name(), Provider: executor.Identifier(), Status: coreauth.StatusActive}
			if _, err := manager.Register(t.Context(), auth); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "overflow-model"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
			router := gin.New()
			router.GET("/v1/responses", h.ResponsesWebsocket)
			server := httptest.NewServer(router)
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			pong := make(chan struct{})
			conn.SetPongHandler(func(string) error { close(pong); return nil })
			results := make(chan websocketClientRead, 8)
			go func() {
				for {
					kind, payload, err := conn.ReadMessage()
					results <- websocketClientRead{messageType: kind, payload: payload, err: err}
					if err != nil {
						return
					}
				}
			}()
			request := []byte(`{"type":"response.create","model":"overflow-model","input":[{"role":"user","content":"wait"}]}`)
			writeRequest := func() {
				if err := conn.WriteMessage(websocket.TextMessage, request); err != nil {
					t.Fatal(err)
				}
			}
			expectPong := func() {
				t.Helper()
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				select {
				case <-pong:
				case <-time.After(2 * time.Second):
					t.Fatal("reader stopped processing control frames")
				}
			}
			writeRequest()
			select {
			case <-executor.started:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream did not start")
			}
			for range tc.queued {
				writeRequest()
			}

			if tc.disconnect {
				// The reader is parked on the blocked channel send, so the
				// disconnect surfaces through the failed response write after
				// release instead of an immediate read error — the same point
				// upstream notices it. At most the in-flight request plus the
				// first buffered one (whose response write exposes the closed
				// connection) may run; the rest of the queued pipeline must never
				// reach the upstream executor.
				_ = conn.Close()
				release()
				time.Sleep(250 * time.Millisecond)
				if got := executor.calls.Load(); got < 1 || got > 2 {
					t.Fatalf("executed %d requests after client disconnect, want at most the in-flight request plus one buffered", got)
				}
				return
			}

			if tc.queued == 1 {
				// Only one buffered message: the reader is back in NextReader
				// and answers control frames immediately.
				expectPong()
			}
			release()
			if tc.queued > 1 {
				// The parked reader resumes once the queue drains.
				expectPong()
			}

			total := 1 + tc.queued
			for i := 1; i <= total; i++ {
				result := <-results
				if result.err != nil || gjson.GetBytes(result.payload, "response.id").String() != fmt.Sprintf("overflow-%d", i) {
					t.Fatalf("pipelined response %d: payload=%s error=%v", i, result.payload, result.err)
				}
			}

			// The session stays usable for further requests.
			writeRequest()
			result := <-results
			if result.err != nil || gjson.GetBytes(result.payload, "response.id").String() != fmt.Sprintf("overflow-%d", total+1) {
				t.Fatalf("session not reusable: payload=%s error=%v", result.payload, result.err)
			}
		})
	}
}
