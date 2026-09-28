package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type trackingReader struct {
	read atomic.Bool
}

func (r *trackingReader) Read([]byte) (int, error) {
	r.read.Store(true)
	return 0, nil
}

func TestRequestLimiterRejectsOverloadBeforeReadingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent: 1,
		MaxQueued:     0,
		QueueTimeout:  time.Second,
	})
	started := make(chan struct{})
	release := make(chan struct{})
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("userApiKey", "test-key")
		c.Next()
	})
	router.Use(limiter.Middleware())
	router.POST("/v1/responses", func(c *gin.Context) {
		close(started)
		<-release
		c.Status(http.StatusOK)
	})

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test"}`))
		router.ServeHTTP(httptest.NewRecorder(), request)
	}()
	<-started

	body := &trackingReader{}
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", body)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
	if body.read.Load() {
		t.Fatal("overloaded request body was read")
	}
	if got := recorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}

	close(release)
	<-firstDone
}

func TestRequestLimiterBoundsQueueAndServesQueuedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent: 1,
		MaxQueued:     1,
		QueueTimeout:  time.Second,
	})
	started := make(chan string, 2)
	release := make(chan struct{}, 2)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("userApiKey", "test-key")
		c.Next()
	})
	router.Use(limiter.Middleware())
	router.POST("/v1/responses", func(c *gin.Context) {
		started <- c.GetHeader("X-Request-ID")
		<-release
		c.Status(http.StatusOK)
	})

	requestAsync := func(id string) <-chan int {
		result := make(chan int, 1)
		go func() {
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			request.Header.Set("X-Request-ID", id)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			result <- recorder.Code
		}()
		return result
	}

	first := requestAsync("first")
	if got := <-started; got != "first" {
		t.Fatalf("first started request = %q, want first", got)
	}
	second := requestAsync("second")

	deadline := time.Now().Add(time.Second)
	for limiter.Queued() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := limiter.Queued(); got != 1 {
		t.Fatalf("queued requests = %d, want 1", got)
	}

	thirdRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	thirdRecorder := httptest.NewRecorder()
	router.ServeHTTP(thirdRecorder, thirdRequest)
	if thirdRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("third status = %d, want %d", thirdRecorder.Code, http.StatusTooManyRequests)
	}

	release <- struct{}{}
	if got := <-first; got != http.StatusOK {
		t.Fatalf("first status = %d, want %d", got, http.StatusOK)
	}
	if got := <-started; got != "second" {
		t.Fatalf("second started request = %q, want second", got)
	}
	release <- struct{}{}
	if got := <-second; got != http.StatusOK {
		t.Fatalf("second status = %d, want %d", got, http.StatusOK)
	}
}

func TestRequestLimiterSeparatesWebsocketAndHTTPRequestCapacity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent:           1,
		MaxWebsocketConnections: 1,
		MaxQueued:               0,
		QueueTimeout:            time.Second,
		WebsocketRoute:          websocketRouteMatcher("/v1/responses"),
	})
	websocketStarted := make(chan struct{})
	releaseWebsocket := make(chan struct{})
	t.Cleanup(func() { close(releaseWebsocket) })
	router := gin.New()
	router.Use(limiter.Middleware())
	router.GET("/v1/responses", func(c *gin.Context) {
		if websocket.IsWebSocketUpgrade(c.Request) {
			close(websocketStarted)
			<-releaseWebsocket
		}
		c.Status(http.StatusOK)
	})

	websocketRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		return request
	}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		router.ServeHTTP(httptest.NewRecorder(), websocketRequest())
	}()
	<-websocketStarted

	httpRecorder := httptest.NewRecorder()
	router.ServeHTTP(httpRecorder, httptest.NewRequest(http.MethodGet, "/v1/responses", nil))
	if httpRecorder.Code != http.StatusOK {
		t.Fatalf("HTTP status with websocket capacity occupied = %d, want %d", httpRecorder.Code, http.StatusOK)
	}

	secondWebsocketRecorder := httptest.NewRecorder()
	router.ServeHTTP(secondWebsocketRecorder, websocketRequest())
	if secondWebsocketRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second websocket status = %d, want %d", secondWebsocketRecorder.Code, http.StatusTooManyRequests)
	}

	releaseWebsocket <- struct{}{}
	<-firstDone
}

// websocketRouteMatcher returns the limiter's route predicate for the given
// router-resolved route patterns.
func websocketRouteMatcher(patterns ...string) func(string) bool {
	set := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		set[pattern] = struct{}{}
	}
	return func(pattern string) bool {
		_, ok := set[pattern]
		return ok
	}
}

func TestIsWebsocketUpgradeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Route patterns as the server registers them: the OpenAI Responses
	// endpoints, the always-attached wsrelay gateway, and the parameterized
	// Codex live/realtime sideband endpoints.
	registered := []string{
		"/v1/responses",
		"/backend-api/codex/responses",
		"/v1/ws",
		"/v1/realtime",
		"/v1/live/:call_id",
		"/v1/realtime/calls/:call_id",
	}
	isWebsocketRoute := websocketRouteMatcher(registered...)

	router := gin.New()
	// Keep trailing-slash and method mismatches on the NoRoute path so the test
	// observes the classification instead of a redirect.
	router.RedirectTrailingSlash = false
	classified := false
	router.Use(func(c *gin.Context) {
		classified = isWebsocketUpgradeRequest(c, isWebsocketRoute)
		c.AbortWithStatus(http.StatusOK)
	})
	for _, pattern := range registered {
		router.GET(pattern, func(c *gin.Context) {})
	}
	router.POST("/v1/responses", func(c *gin.Context) {})
	router.POST("/backend-api/codex/responses", func(c *gin.Context) {})
	router.GET("/v1/models", func(c *gin.Context) {})
	router.GET("/v1/realtime/translations", func(c *gin.Context) {})
	router.GET("/openai/v1/responses", func(c *gin.Context) {})

	upgradeHeaders := map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		want    bool
	}{
		{"genuine upgrade to /v1/responses", http.MethodGet, "/v1/responses", upgradeHeaders, true},
		{"genuine upgrade to /backend-api/codex/responses", http.MethodGet, "/backend-api/codex/responses", upgradeHeaders, true},
		{"genuine upgrade to the attached /v1/ws gateway", http.MethodGet, "/v1/ws", upgradeHeaders, true},
		{"genuine upgrade to /v1/realtime", http.MethodGet, "/v1/realtime", upgradeHeaders, true},
		{"genuine upgrade to a parameterized /v1/live/:call_id", http.MethodGet, "/v1/live/call-123", upgradeHeaders, true},
		{"genuine upgrade to a parameterized /v1/realtime/calls/:call_id", http.MethodGet, "/v1/realtime/calls/call-123", upgradeHeaders, true},
		{"mixed-case comma-token upgrade to /v1/responses", http.MethodGet, "/v1/responses", map[string]string{"Connection": "keep-alive, Upgrade", "Upgrade": "WebSocket"}, true},
		{"spoofed post to /v1/responses", http.MethodPost, "/v1/responses", upgradeHeaders, false},
		{"spoofed post to /backend-api/codex/responses", http.MethodPost, "/backend-api/codex/responses", upgradeHeaders, false},
		{"upgrade headers on a registered non-websocket route", http.MethodGet, "/v1/models", upgradeHeaders, false},
		{"upgrade headers on the registered realtime translations route", http.MethodGet, "/v1/realtime/translations", upgradeHeaders, false},
		{"upgrade headers under /openai/v1", http.MethodGet, "/openai/v1/responses", upgradeHeaders, false},
		{"plain get to /v1/responses", http.MethodGet, "/v1/responses", nil, false},
		{"upgrade headers with non-exact path", http.MethodGet, "/v1/responses/", upgradeHeaders, false},
		{"upgrade headers on unregistered route", http.MethodGet, "/unregistered", upgradeHeaders, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			for name, value := range tc.headers {
				request.Header.Set(name, value)
			}
			classified = false
			router.ServeHTTP(httptest.NewRecorder(), request)
			if classified != tc.want {
				t.Fatalf("isWebsocketUpgradeRequest() = %v, want %v", classified, tc.want)
			}
		})
	}

	if isWebsocketUpgradeRequest(nil, isWebsocketRoute) {
		t.Fatal("nil context must not qualify as a websocket upgrade")
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	for name, value := range upgradeHeaders {
		request.Header.Set(name, value)
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = request
	if isWebsocketUpgradeRequest(c, nil) {
		t.Fatal("a nil route predicate must not qualify a request as a websocket upgrade")
	}
}

func TestRequestLimiterRoutesSpoofedWebsocketUpgradesThroughHTTPLane(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent:           1,
		MaxWebsocketConnections: 1,
		MaxQueued:               0,
		QueueTimeout:            time.Second,
		WebsocketRoute:          websocketRouteMatcher("/v1/responses", "/backend-api/codex/responses", "/v1/ws", "/v1/realtime", "/v1/live/:call_id", "/v1/realtime/calls/:call_id"),
	})
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("userApiKey", "test-key")
		c.Next()
	})
	router.Use(limiter.Middleware())

	holderEntered := make(chan struct{})
	holderRelease := make(chan struct{})
	hold := func(c *gin.Context) {
		select {
		case <-holderEntered:
		default:
			close(holderEntered)
			<-holderRelease
		}
		c.Status(http.StatusOK)
	}
	router.POST("/v1/responses", hold)
	router.POST("/backend-api/codex/responses", hold)
	router.GET("/v1/models", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.GET("/openai/v1/videos/:video_id", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Occupy all ordinary HTTP capacity with a plain non-WebSocket POST.
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/responses", nil))
	}()
	<-holderEntered
	defer func() {
		close(holderRelease)
		<-holderDone
	}()

	tests := []struct {
		name       string
		method     string
		path       string
		connection string
		upgrade    string
	}{
		{"spoofed post to /v1/responses", http.MethodPost, "/v1/responses", "Upgrade", "websocket"},
		{"spoofed post to /backend-api/codex/responses", http.MethodPost, "/backend-api/codex/responses", "Upgrade", "websocket"},
		{"mixed-case comma-token get /v1/models", http.MethodGet, "/v1/models", "keep-alive, Upgrade", "WebSocket"},
		{"comma-token get under /openai/v1", http.MethodGet, "/openai/v1/videos/video-123", "keep-alive, Upgrade", "websocket"},
		{"upgrade headers on unregistered route", http.MethodGet, "/unregistered", "Upgrade", "websocket"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Connection", tc.connection)
			request.Header.Set("Upgrade", tc.upgrade)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
			}
		})
	}
}

func TestRequestLimiterAdmitsGenuineWebsocketUpgradesOnRegisteredPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent:           1,
		MaxWebsocketConnections: 2,
		MaxQueued:               0,
		QueueTimeout:            time.Second,
		WebsocketRoute:          websocketRouteMatcher("/v1/responses", "/backend-api/codex/responses"),
	})
	router := gin.New()
	router.Use(limiter.Middleware())

	httpStarted := make(chan struct{})
	httpRelease := make(chan struct{})
	router.POST("/v1/responses", func(c *gin.Context) {
		close(httpStarted)
		<-httpRelease
		c.Status(http.StatusOK)
	})

	websocketStarted := make(chan string, 2)
	websocketRelease := make(chan struct{}, 2)
	websocketHandler := func(c *gin.Context) {
		websocketStarted <- c.Request.URL.Path
		<-websocketRelease
		c.Status(http.StatusOK)
	}
	router.GET("/v1/responses", websocketHandler)
	router.GET("/backend-api/codex/responses", websocketHandler)

	// Occupy all ordinary HTTP capacity with a plain non-WebSocket POST.
	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/responses", nil))
	}()
	<-httpStarted
	defer func() {
		close(httpRelease)
		<-httpDone
	}()

	// Genuine WebSocket upgrades to both registered downstream endpoints still
	// use the independent WebSocket semaphore while HTTP capacity is full.
	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses"} {
		done := make(chan int, 1)
		go func() {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Upgrade", "websocket")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			done <- recorder.Code
		}()
		if got := <-websocketStarted; got != path {
			t.Fatalf("websocket handler path = %q, want %q", got, path)
		}
		websocketRelease <- struct{}{}
		if got := <-done; got != http.StatusOK {
			t.Fatalf("websocket status for %s = %d, want %d", path, got, http.StatusOK)
		}
	}
}

func TestRequestLimiterReleasesWebsocketPermit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limiter := NewRequestLimiter(RequestLimitOptions{
		MaxConcurrent:           1,
		MaxWebsocketConnections: 1,
		MaxQueued:               0,
		QueueTimeout:            time.Second,
		WebsocketRoute:          websocketRouteMatcher("/backend-api/codex/responses"),
	})
	router := gin.New()
	router.Use(limiter.Middleware())

	started := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	router.GET("/backend-api/codex/responses", func(c *gin.Context) {
		started <- struct{}{}
		<-release
		c.Status(http.StatusOK)
	})

	websocketRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/backend-api/codex/responses", nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		return request
	}

	firstDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, websocketRequest())
		firstDone <- recorder.Code
	}()
	<-started

	// The single WebSocket permit is held, so a second upgrade is rejected.
	secondRecorder := httptest.NewRecorder()
	router.ServeHTTP(secondRecorder, websocketRequest())
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second websocket status = %d, want %d", secondRecorder.Code, http.StatusTooManyRequests)
	}

	// Releasing the first connection frees the permit for the next upgrade.
	release <- struct{}{}
	if got := <-firstDone; got != http.StatusOK {
		t.Fatalf("first websocket status = %d, want %d", got, http.StatusOK)
	}

	thirdDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, websocketRequest())
		thirdDone <- recorder.Code
	}()
	<-started
	release <- struct{}{}
	if got := <-thirdDone; got != http.StatusOK {
		t.Fatalf("third websocket status = %d, want %d", got, http.StatusOK)
	}
}
