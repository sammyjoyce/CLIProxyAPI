package helps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestRequestLoggingDoesNotMarkUpstreamAttempt(t *testing.T) {
	tests := []struct {
		name   string
		record func(context.Context)
	}{
		{
			name: "HTTP",
			record: func(ctx context.Context) {
				RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{URL: "https://api.example.com", Method: http.MethodPost})
			},
		},
		{
			name: "websocket",
			record: func(ctx context.Context) {
				RecordAPIWebsocketRequest(ctx, &config.Config{}, UpstreamRequestLog{URL: "wss://api.example.com", Method: "WEBSOCKET"})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := cliproxyexecutor.WithUpstreamAttemptTracker(context.Background())
			test.record(ctx)
			if cliproxyexecutor.UpstreamAttempted(ctx) {
				t.Fatal("request logging marked an upstream attempt before transport")
			}
		})
	}
}

func TestRecordAPIRequestClonesDeferredBodyWhenRequestLogDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	body := []byte(`{"model":"original"}`)

	RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{
		URL:    "https://api.example.com/v1/responses",
		Method: http.MethodPost,
		Body:   body,
	})
	body[10] = 'X'

	value, exists := ginCtx.Get(logging.DeferredAPIRequestContextKey)
	if !exists {
		t.Fatal("deferred API request was not captured")
	}
	requests, ok := value.([]logging.DeferredAPIRequest)
	if !ok || len(requests) != 1 {
		t.Fatalf("deferred API requests = %#v, want one request", value)
	}
	captured := string(requests[0]())
	if !strings.Contains(captured, `{"model":"original"}`) {
		t.Fatalf("captured API request = %q, want original body", captured)
	}
}

func TestRecordAPIRequestBoundsDeferredWebsocketBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
	body := bytes.Repeat([]byte("x"), 2<<20)

	RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{Body: body})

	capturedBytes, _ := ginCtx.Get(deferredAPIRequestBytesKey)
	if capturedBytes != 1<<20 {
		t.Fatalf("captured bytes = %v, want %d", capturedBytes, 1<<20)
	}
	value, exists := ginCtx.Get(logging.DeferredAPIRequestContextKey)
	if !exists {
		t.Fatal("deferred API request was not captured")
	}
	requests, ok := value.([]logging.DeferredAPIRequest)
	if !ok || len(requests) != 1 {
		t.Fatalf("deferred API requests = %#v, want one request", value)
	}
	captured := string(requests[0]())
	if !strings.Contains(captured, "[API REQUEST BODY TRUNCATED: captured first 1048576 bytes]") {
		t.Fatal("deferred WebSocket API request is missing truncation marker")
	}
}

func newDeferredTestContext(downstream bool) (context.Context, *gin.Context) {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	if downstream {
		ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
	}
	return ctx, ginCtx
}

func deferredAPIRequests(t *testing.T, ginCtx *gin.Context) []logging.DeferredAPIRequest {
	t.Helper()
	value, exists := ginCtx.Get(logging.DeferredAPIRequestContextKey)
	if !exists {
		return nil
	}
	requests, ok := value.([]logging.DeferredAPIRequest)
	if !ok {
		t.Fatalf("deferred API requests = %#v, want []logging.DeferredAPIRequest", value)
	}
	return requests
}

// materializeDeferredAPIRequests renders deferred closures using the same bounded loop contract
// as response_writer.go's extractDeferredAPIRequest.
func materializeDeferredAPIRequests(t *testing.T, ginCtx *gin.Context) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, buildRequest := range deferredAPIRequests(t, ginCtx) {
		if buildRequest == nil {
			continue
		}
		body.Write(buildRequest())
	}
	return body.Bytes()
}

func deferredBodyBytesUsed(t *testing.T, ginCtx *gin.Context) int {
	t.Helper()
	capturedBytes, _ := ginCtx.Get(deferredAPIRequestBytesKey)
	bytesUsed, _ := capturedBytes.(int)
	return bytesUsed
}

func stubDeferredLogTime(t *testing.T, timestamp time.Time) {
	t.Helper()
	original := deferredLogTimeNow
	deferredLogTimeNow = func() time.Time { return timestamp }
	t.Cleanup(func() { deferredLogTimeNow = original })
}

func TestRecordAPIRequestDownstreamWebsocketFloodBounds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, ginCtx := newDeferredTestContext(true)
	cfg := &config.Config{}

	// Fill the 1 MiB deferred body budget exactly.
	fillBody := bytes.Repeat([]byte("f"), (1<<20)/4)
	for i := 0; i < 4; i++ {
		RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
			URL:    "https://api.example.com/v1/responses",
			Method: http.MethodPost,
			Body:   fillBody,
		})
	}
	if got := deferredBodyBytesUsed(t, ginCtx); got != 1<<20 {
		t.Fatalf("captured body bytes = %d, want %d", got, 1<<20)
	}
	if got := len(deferredAPIRequests(t, ginCtx)); got != 4 {
		t.Fatalf("deferred API requests after body fill = %d, want 4", got)
	}

	floodBody := bytes.Repeat([]byte("x"), 32)
	truncatedSeen := false
	for i := 0; i < 10000; i++ {
		RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
			URL:    "https://api.example.com/v1/responses",
			Method: http.MethodPost,
			Body:   floodBody,
		})
		if got := deferredBodyBytesUsed(t, ginCtx); got > 1<<20 {
			t.Fatalf("call %d: captured body bytes = %d, exceeds %d", i, got, 1<<20)
		}
		if got := len(deferredAPIRequests(t, ginCtx)); got > 129 {
			t.Fatalf("call %d: deferred API requests = %d, exceeds 129", i, got)
		}
		state := getDeferredWebsocketLogState(ginCtx)
		if state.renderedBytes > maxDeferredWebsocketRenderedBytes {
			t.Fatalf("call %d: rendered bytes = %d, exceeds %d", i, state.renderedBytes, maxDeferredWebsocketRenderedBytes)
		}
		if truncatedSeen && !state.truncated {
			t.Fatalf("call %d: truncation state was reset after becoming terminal", i)
		}
		truncatedSeen = truncatedSeen || state.truncated
	}
	if !truncatedSeen {
		t.Fatal("downstream deferred log never became terminal")
	}

	state := getDeferredWebsocketLogState(ginCtx)
	if !state.truncated {
		t.Fatal("downstream deferred log is not terminal after flood")
	}
	requests := deferredAPIRequests(t, ginCtx)
	if len(requests) != 129 {
		t.Fatalf("deferred API requests = %d, want 129 (128 useful + 1 marker)", len(requests))
	}
	materialized := materializeDeferredAPIRequests(t, ginCtx)
	if len(materialized) > maxDeferredWebsocketRenderedBytes {
		t.Fatalf("materialized output = %d bytes, exceeds %d", len(materialized), maxDeferredWebsocketRenderedBytes)
	}
	if got := bytes.Count(materialized, []byte(deferredWebsocketTruncationMarker)); got != 1 {
		t.Fatalf("truncation markers = %d, want exactly 1", got)
	}
	if got := string(requests[len(requests)-1]()); got != deferredWebsocketTruncationMarker {
		t.Fatalf("last deferred entry = %q, want truncation marker", got)
	}
	if !bytes.HasSuffix(materialized, []byte(deferredWebsocketTruncationMarker)) {
		t.Fatal("materialized output does not end with the truncation marker")
	}
	if got := deferredBodyBytesUsed(t, ginCtx); got != 1<<20 {
		t.Fatalf("captured body bytes = %d, want exactly %d", got, 1<<20)
	}

	// Later calls must be complete no-ops: state, slice contents, and materialized output stay identical.
	beforeState := getDeferredWebsocketLogState(ginCtx)
	beforeLen := len(deferredAPIRequests(t, ginCtx))
	beforeBodyBytes := deferredBodyBytesUsed(t, ginCtx)
	for i := 0; i < 500; i++ {
		RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
			URL:    "https://api.example.com/v1/responses",
			Method: http.MethodPost,
			Body:   floodBody,
		})
	}
	if afterState := getDeferredWebsocketLogState(ginCtx); afterState != beforeState {
		t.Fatalf("state changed after terminal: before=%+v after=%+v", beforeState, afterState)
	}
	if got := len(deferredAPIRequests(t, ginCtx)); got != beforeLen {
		t.Fatalf("deferred API requests = %d, want unchanged %d", got, beforeLen)
	}
	if got := deferredBodyBytesUsed(t, ginCtx); got != beforeBodyBytes {
		t.Fatalf("captured body bytes = %d, want unchanged %d", got, beforeBodyBytes)
	}
	if got := materializeDeferredAPIRequests(t, ginCtx); !bytes.Equal(got, materialized) {
		t.Fatal("materialized output changed after terminal state")
	}
}

func TestRecordAPIRequestDownstreamWebsocketCountBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, ginCtx := newDeferredTestContext(true)
	cfg := &config.Config{}
	body := []byte(`{"n":1}`)
	info := func() UpstreamRequestLog {
		return UpstreamRequestLog{
			URL:    "https://api.example.com/v1/responses",
			Method: http.MethodPost,
			Body:   body,
		}
	}

	for i := 0; i < maxDeferredWebsocketUsefulEntries; i++ {
		RecordAPIRequest(ctx, cfg, info())
	}
	requests := deferredAPIRequests(t, ginCtx)
	if len(requests) != maxDeferredWebsocketUsefulEntries {
		t.Fatalf("deferred API requests = %d, want %d", len(requests), maxDeferredWebsocketUsefulEntries)
	}
	for i, buildRequest := range requests {
		rendered := string(buildRequest())
		wantPrefix := fmt.Sprintf("=== API REQUEST %d ===\n", i+1)
		if !strings.HasPrefix(rendered, wantPrefix) {
			t.Fatalf("entry %d prefix = %q, want %q (numbering/order must remain stable)", i, rendered[:min(len(rendered), 32)], wantPrefix)
		}
	}

	// Request 129 appends only the marker and turns the state terminal.
	RecordAPIRequest(ctx, cfg, info())
	requests = deferredAPIRequests(t, ginCtx)
	if len(requests) != maxDeferredWebsocketUsefulEntries+1 {
		t.Fatalf("deferred API requests = %d, want %d", len(requests), maxDeferredWebsocketUsefulEntries+1)
	}
	for i := 0; i < maxDeferredWebsocketUsefulEntries; i++ {
		rendered := string(requests[i]())
		wantPrefix := fmt.Sprintf("=== API REQUEST %d ===\n", i+1)
		if !strings.HasPrefix(rendered, wantPrefix) {
			t.Fatalf("entry %d prefix changed after marker, got %q, want %q", i, rendered[:min(len(rendered), 32)], wantPrefix)
		}
	}
	if got := string(requests[maxDeferredWebsocketUsefulEntries]()); got != deferredWebsocketTruncationMarker {
		t.Fatalf("entry %d = %q, want truncation marker", maxDeferredWebsocketUsefulEntries, got)
	}
	materialized := materializeDeferredAPIRequests(t, ginCtx)
	if got := strings.Count(string(materialized), "=== API REQUEST "); got != maxDeferredWebsocketUsefulEntries {
		t.Fatalf("materialized API request entries = %d, want %d", got, maxDeferredWebsocketUsefulEntries)
	}
	if got := deferredBodyBytesUsed(t, ginCtx); got != maxDeferredWebsocketUsefulEntries*len(body) {
		t.Fatalf("captured body bytes = %d, want %d (marker request must not commit body bytes)", got, maxDeferredWebsocketUsefulEntries*len(body))
	}
	if state := getDeferredWebsocketLogState(ginCtx); !state.truncated {
		t.Fatal("downstream deferred log is not terminal after the marker request")
	}

	// Every subsequent call is a complete no-op.
	for i := 0; i < 50; i++ {
		RecordAPIRequest(ctx, cfg, info())
	}
	if got := len(deferredAPIRequests(t, ginCtx)); got != maxDeferredWebsocketUsefulEntries+1 {
		t.Fatalf("deferred API requests = %d, want unchanged %d", got, maxDeferredWebsocketUsefulEntries+1)
	}
	if got := materializeDeferredAPIRequests(t, ginCtx); !bytes.Equal(got, materialized) {
		t.Fatal("materialized output changed after terminal state")
	}
}

func TestRecordAPIRequestDownstreamWebsocketRenderedByteBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fixedTimestamp := time.Date(2025, 1, 2, 3, 4, 5, 123456789, time.UTC)
	stubDeferredLogTime(t, fixedTimestamp)
	cfg := &config.Config{}

	fillerInfo := func() UpstreamRequestLog {
		return UpstreamRequestLog{
			URL:    "https://api.example.com/" + strings.Repeat("u", 1<<20),
			Method: http.MethodPost,
			Body:   bytes.Repeat([]byte("b"), 100),
		}
	}
	candidateURL := "https://api.example.com/v1/chat"
	candidatePrefixLen := len(newAPIRequestLogBuilder(2, UpstreamRequestLog{URL: candidateURL, Method: http.MethodPost}, fixedTimestamp).String())

	// expectedRender builds the exact bytes an admitted deferred closure must return.
	expectedRender := func(index int, info UpstreamRequestLog) []byte {
		builder := newAPIRequestLogBuilder(index, info, fixedTimestamp)
		builder.Write(info.Body)
		builder.WriteString("\n\n")
		return []byte(builder.String())
	}

	t.Run("exact fit admitted then marker", func(t *testing.T) {
		ctx, ginCtx := newDeferredTestContext(true)
		filler := fillerInfo()
		RecordAPIRequest(ctx, cfg, filler)
		fillerRender := expectedRender(1, filler)
		requests := deferredAPIRequests(t, ginCtx)
		if len(requests) != 1 {
			t.Fatalf("deferred API requests = %d, want 1", len(requests))
		}
		if got := requests[0](); !bytes.Equal(got, fillerRender) {
			t.Fatal("filler render does not exactly match newAPIRequestLogBuilder output")
		}
		if got := getDeferredWebsocketLogState(ginCtx).renderedBytes; got != len(fillerRender) {
			t.Fatalf("rendered bytes = %d, want %d", got, len(fillerRender))
		}

		allowance := maxDeferredWebsocketRenderedBytes - len(deferredWebsocketTruncationMarker) - len(fillerRender)
		candidateBodyLen := allowance - candidatePrefixLen - len("\n\n")
		if candidateBodyLen < 1 || 100+candidateBodyLen > maxDeferredWebsocketBodyBytes {
			t.Fatalf("test setup: candidate body length %d out of range", candidateBodyLen)
		}
		candidate := UpstreamRequestLog{URL: candidateURL, Method: http.MethodPost, Body: bytes.Repeat([]byte("c"), candidateBodyLen)}
		RecordAPIRequest(ctx, cfg, candidate)
		candidateRender := expectedRender(2, candidate)
		if len(candidateRender) != allowance {
			t.Fatalf("test setup: candidate render = %d bytes, want exact allowance %d", len(candidateRender), allowance)
		}
		requests = deferredAPIRequests(t, ginCtx)
		if len(requests) != 2 {
			t.Fatalf("deferred API requests = %d, want 2 (exact-fit candidate must be admitted)", len(requests))
		}
		if got := requests[1](); !bytes.Equal(got, candidateRender) {
			t.Fatal("exact-fit candidate render does not exactly match newAPIRequestLogBuilder output")
		}
		if got := deferredBodyBytesUsed(t, ginCtx); got != 100+candidateBodyLen {
			t.Fatalf("captured body bytes = %d, want %d", got, 100+candidateBodyLen)
		}
		if got := getDeferredWebsocketLogState(ginCtx).renderedBytes; got != maxDeferredWebsocketRenderedBytes-len(deferredWebsocketTruncationMarker) {
			t.Fatalf("rendered bytes = %d, want %d", got, maxDeferredWebsocketRenderedBytes-len(deferredWebsocketTruncationMarker))
		}

		// The following request exceeds the zero remaining allowance and only adds the marker.
		RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: candidateURL, Method: http.MethodPost, Body: []byte("d")})
		requests = deferredAPIRequests(t, ginCtx)
		if len(requests) != 3 {
			t.Fatalf("deferred API requests = %d, want 3 (filler + candidate + marker)", len(requests))
		}
		if got := string(requests[2]()); got != deferredWebsocketTruncationMarker {
			t.Fatalf("last deferred entry = %q, want truncation marker", got)
		}
		state := getDeferredWebsocketLogState(ginCtx)
		if !state.truncated {
			t.Fatal("downstream deferred log is not terminal after the marker")
		}
		if state.renderedBytes != maxDeferredWebsocketRenderedBytes {
			t.Fatalf("rendered bytes = %d, want exactly %d", state.renderedBytes, maxDeferredWebsocketRenderedBytes)
		}
		if got := materializeDeferredAPIRequests(t, ginCtx); len(got) != maxDeferredWebsocketRenderedBytes {
			t.Fatalf("materialized output = %d bytes, want exactly %d", len(got), maxDeferredWebsocketRenderedBytes)
		}
	})

	t.Run("one byte over omitted for marker", func(t *testing.T) {
		ctx, ginCtx := newDeferredTestContext(true)
		filler := fillerInfo()
		RecordAPIRequest(ctx, cfg, filler)
		fillerRender := expectedRender(1, filler)

		allowance := maxDeferredWebsocketRenderedBytes - len(deferredWebsocketTruncationMarker) - len(fillerRender)
		candidateBodyLen := allowance - candidatePrefixLen - len("\n\n") + 1
		if candidateBodyLen < 1 || 100+candidateBodyLen > maxDeferredWebsocketBodyBytes {
			t.Fatalf("test setup: candidate body length %d out of range", candidateBodyLen)
		}
		candidate := UpstreamRequestLog{URL: candidateURL, Method: http.MethodPost, Body: bytes.Repeat([]byte("c"), candidateBodyLen)}
		RecordAPIRequest(ctx, cfg, candidate)

		requests := deferredAPIRequests(t, ginCtx)
		if len(requests) != 2 {
			t.Fatalf("deferred API requests = %d, want 2 (filler + marker only)", len(requests))
		}
		if got := requests[0](); !bytes.Equal(got, fillerRender) {
			t.Fatal("filler render changed after omission")
		}
		if got := string(requests[1]()); got != deferredWebsocketTruncationMarker {
			t.Fatalf("entry 1 = %q, want truncation marker", got)
		}
		// Candidate body bytes were not committed; only the marker was accounted beyond the filler.
		if got := deferredBodyBytesUsed(t, ginCtx); got != 100 {
			t.Fatalf("captured body bytes = %d, want 100 (omitted candidate must not commit body bytes)", got)
		}
		state := getDeferredWebsocketLogState(ginCtx)
		if !state.truncated {
			t.Fatal("downstream deferred log is not terminal after omission")
		}
		if want := len(fillerRender) + len(deferredWebsocketTruncationMarker); state.renderedBytes != want {
			t.Fatalf("rendered bytes = %d, want %d (filler + marker only)", state.renderedBytes, want)
		}
		materialized := materializeDeferredAPIRequests(t, ginCtx)
		if want := len(fillerRender) + len(deferredWebsocketTruncationMarker); len(materialized) != want {
			t.Fatalf("materialized output = %d bytes, want %d", len(materialized), want)
		}
		if bytes.Contains(materialized, bytes.Repeat([]byte("c"), 64)) {
			t.Fatal("omitted candidate body leaked into deferred output")
		}
	})
}

func TestRecordAPIRequestDownstreamWebsocketMasksAndPrerenders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, ginCtx := newDeferredTestContext(true)
	cfg := &config.Config{}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer sk-secret-token-1234567890")
	headers.Set("X-Api-Key", "api-key-value-123456789")
	headers.Set("X-Token", "token-value-123456789")
	headers.Set("X-Secret", "secret-value-123456789")
	body := []byte(`{"prompt":"sensitive-body-content-12345"}`)
	RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
		URL:       "https://api.example.com/v1/responses",
		Method:    http.MethodPost,
		Headers:   headers,
		Body:      body,
		Provider:  "test-provider",
		AuthType:  "api_key",
		AuthValue: "auth-secret-value-123456789",
	})

	requests := deferredAPIRequests(t, ginCtx)
	if len(requests) != 1 {
		t.Fatalf("deferred API requests = %d, want 1", len(requests))
	}
	rendered := string(requests[0]())
	for _, secret := range []string{
		"sk-secret-token-1234567890",
		"api-key-value-123456789",
		"token-value-123456789",
		"secret-value-123456789",
		"auth-secret-value-123456789",
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("deferred output contains unmasked secret %q", secret)
		}
	}
	for _, masked := range []string{
		"Bearer sk-s...7890",
		"api-...6789",
		"toke...6789",
		"secr...6789",
		"value=auth...6789",
		"sensitive-body-content-12345",
	} {
		if !strings.Contains(rendered, masked) {
			t.Fatalf("deferred output is missing %q", masked)
		}
	}

	// Mutate the original headers, body, and auth source values after recording; the deferred
	// output must remain the original masked, pre-rendered content.
	headers.Set("Authorization", "Bearer mutated-after-record-0000000000")
	headers.Set("X-Api-Key", "mutated-key-after-record-000000")
	headers.Set("X-Token", "mutated-token-after-record-000000")
	headers.Set("X-Secret", "mutated-secret-after-record-000000")
	body[12] = 'X'
	// AuthValue and other scalar fields were passed by value and fully rendered at record time,
	// so only the shared header map and body slice can exercise post-record mutation.

	after := string(requests[0]())
	if after != rendered {
		t.Fatal("deferred output changed after mutating source header, body, and auth values")
	}
	for _, mutated := range []string{"mutated-after-record", "mutated-key-after-record", "mutated-token-after-record", "mutated-secret-after-record"} {
		if strings.Contains(after, mutated) {
			t.Fatalf("deferred output contains mutated source value %q", mutated)
		}
	}
}

func TestRecordAPIRequestNonDownstreamDeferredExceedsDownstreamCap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, ginCtx := newDeferredTestContext(false)
	cfg := &config.Config{}
	body := []byte(`{"n":1}`)
	headers := http.Header{}
	headers.Set("X-Custom", "initial")

	const total = maxDeferredWebsocketUsefulEntries + 72
	for i := 0; i < total; i++ {
		RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
			URL:     "https://api.example.com/v1/responses",
			Method:  http.MethodPost,
			Headers: headers,
			Body:    body,
		})
	}
	requests := deferredAPIRequests(t, ginCtx)
	if len(requests) != total {
		t.Fatalf("non-downstream deferred API requests = %d, want %d (no downstream cap)", len(requests), total)
	}
	if got := deferredBodyBytesUsed(t, ginCtx); got != total*len(body) {
		t.Fatalf("captured body bytes = %d, want %d", got, total*len(body))
	}
	materialized := materializeDeferredAPIRequests(t, ginCtx)
	if bytes.Contains(materialized, []byte(deferredWebsocketTruncationMarker)) {
		t.Fatal("non-downstream deferred log unexpectedly contains the downstream truncation marker")
	}
	if got := strings.Count(string(materialized), "=== API REQUEST "); got != total {
		t.Fatalf("materialized API request entries = %d, want %d", got, total)
	}
	if _, exists := ginCtx.Get(deferredWebsocketStateKey); exists {
		t.Fatal("non-downstream path created downstream websocket state")
	}
	if got := string(requests[0]()); !strings.HasPrefix(got, "=== API REQUEST 1 ===\n") {
		t.Fatalf("first entry prefix = %q, want request 1", got[:min(len(got), 32)])
	}
	if got := string(requests[total-1]()); !strings.HasPrefix(got, fmt.Sprintf("=== API REQUEST %d ===\n", total)) {
		t.Fatalf("last entry prefix = %q, want request %d", got[:min(len(got), 32)], total)
	}

	// Existing clone/lazy semantics are preserved: bodies are cloned at capture time, while
	// headers are captured by reference and rendered lazily when the closure runs.
	headers.Set("X-Custom", "mutated")
	if got := string(requests[total-1]()); !strings.Contains(got, "X-Custom: mutated") {
		t.Fatal("non-downstream deferred render lost its lazy header semantics")
	}
}

func TestRecordAPIRequestDownstreamWebsocketRequestLogEnabledSkipsDeferredState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, ginCtx := newDeferredTestContext(true)
	cfg := &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}

	RecordAPIRequest(ctx, cfg, UpstreamRequestLog{
		URL:    "https://api.example.com/v1/responses",
		Method: http.MethodPost,
		Body:   []byte(`{"n":1}`),
	})

	if _, exists := ginCtx.Get(logging.DeferredAPIRequestContextKey); exists {
		t.Fatal("deferred API requests were created while request logging is enabled")
	}
	if _, exists := ginCtx.Get(deferredWebsocketStateKey); exists {
		t.Fatal("downstream deferred state was created while request logging is enabled")
	}
	if _, exists := ginCtx.Get(deferredAPIRequestBytesKey); exists {
		t.Fatal("deferred body accounting was created while request logging is enabled")
	}
	if attempts := getAttempts(ginCtx); len(attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(attempts))
	}
	value, exists := ginCtx.Get(apiRequestKey)
	if !exists {
		t.Fatal("normal request log path did not capture the request")
	}
	if apiRequest, ok := value.([]byte); !ok || !bytes.Contains(apiRequest, []byte("=== API REQUEST 1 ===")) {
		t.Fatalf("normal request log capture = %#v, want rendered request 1", value)
	}
}

func TestRecordAPIResponseMetadataStoresHeadersWhenRequestLogDisabled(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	headers := http.Header{}
	headers.Add("X-Upstream-Request-Id", "upstream-req-1")

	RecordAPIResponseMetadata(ctx, &config.Config{}, http.StatusOK, headers)
	headers.Set("X-Upstream-Request-Id", "mutated")

	got := logging.GetResponseHeaders(ctx)
	if got.Get("X-Upstream-Request-Id") != "upstream-req-1" {
		t.Fatalf("response header = %q, want %q", got.Get("X-Upstream-Request-Id"), "upstream-req-1")
	}
}

func TestAPIResponseAttemptsAreSeparated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name              string
		fileBacked        bool
		firstResponseBody []byte
	}{
		{name: "memory backed error"},
		{name: "file backed error", fileBacked: true},
		{name: "memory backed partial body", firstResponseBody: []byte("partial")},
		{name: "file backed partial body", fileBacked: true, firstResponseBody: []byte("partial")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(recorder)
			var responseSource *logging.FileBodySource
			if tt.fileBacked {
				var errSource error
				responseSource, errSource = logging.NewFileBodySourceInDir(t.TempDir(), "api-response")
				if errSource != nil {
					t.Fatalf("NewFileBodySourceInDir: %v", errSource)
				}
				t.Cleanup(func() {
					if errCleanup := responseSource.Cleanup(); errCleanup != nil {
						t.Errorf("Cleanup: %v", errCleanup)
					}
				})
				ginCtx.Set(logging.APIResponseSourceContextKey, responseSource)
			}

			ctx := context.WithValue(context.Background(), "gin", ginCtx)
			cfg := &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}
			RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://api.example.com/first", Method: http.MethodPost})
			if len(tt.firstResponseBody) > 0 {
				AppendAPIResponseChunk(ctx, cfg, tt.firstResponseBody)
			} else {
				RecordAPIResponseError(ctx, cfg, errors.New("EOF"))
			}
			RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://api.example.com/second", Method: http.MethodPost})
			RecordAPIResponseError(ctx, cfg, errors.New("retry failed"))

			var response []byte
			if responseSource != nil {
				var errBytes error
				response, errBytes = responseSource.Bytes()
				if errBytes != nil {
					t.Fatalf("responseSource.Bytes: %v", errBytes)
				}
			} else {
				value, exists := ginCtx.Get(apiResponseKey)
				if !exists {
					t.Fatal("API_RESPONSE was not captured")
				}
				response, _ = value.([]byte)
			}

			previousEnd := "Error: EOF"
			if len(tt.firstResponseBody) > 0 {
				previousEnd = string(tt.firstResponseBody)
			}
			wantBoundary := previousEnd + "\n\n=== API RESPONSE 2 ==="
			if !strings.Contains(string(response), wantBoundary) {
				t.Fatalf("API response attempts are not separated by one blank line:\n%q\nwant boundary %q", response, wantBoundary)
			}
		})
	}
}
