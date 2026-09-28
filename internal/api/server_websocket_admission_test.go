package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gin "github.com/gin-gonic/gin"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestWebsocketRouteSetTracksRegisteredUpgradeRoutes pins the request limiter's
// dedicated websocket lane to the routes the server registers: every websocket
// upgrade endpoint must be classified as one, every classified route must exist
// on the engine, and ordinary routes must stay out of the set.
func TestWebsocketRouteSetTracksRegisteredUpgradeRoutes(t *testing.T) {
	server := newTestServer(t)
	server.AttachWebsocketRoute("/v1/ws", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	want := []string{
		"/v1/responses",
		"/backend-api/codex/responses",
		"/v1/realtime",
		"/v1/live/:call_id",
		"/v1/realtime/calls/:call_id",
		"/v1/ws",
	}
	registeredGet := make(map[string]struct{})
	for _, route := range server.engine.Routes() {
		if route.Method == http.MethodGet {
			registeredGet[route.Path] = struct{}{}
		}
	}
	for _, pattern := range want {
		if !server.wsRoutes.contains(pattern) {
			t.Errorf("websocket route set is missing registered upgrade route %q", pattern)
		}
		if _, ok := registeredGet[pattern]; !ok {
			t.Errorf("websocket route set claims %q but no GET route is registered for it", pattern)
		}
	}
	for _, pattern := range []string{"/v1/models", "/v1beta/models", "/v1/realtime/translations", "/v1/responses/compact", "/healthz"} {
		if server.wsRoutes.contains(pattern) {
			t.Errorf("non-websocket route %q is classified as a websocket upgrade route", pattern)
		}
	}
}

// TestWebsocketUpgradeEndpointsUseDedicatedAdmissionLane proves the dedicated
// websocket lane follows the registered upgrade routes instead of a partial
// list: while the single global slot is occupied, genuine upgrades to every
// registered websocket endpoint still reach their handlers, while spoofed
// upgrade headers and non-upgrade requests stay on the saturated global lane.
func TestWebsocketUpgradeEndpointsUseDedicatedAdmissionLane(t *testing.T) {
	server := newTestServerWithConfigMutation(t, func(cfg *proxyconfig.Config) {
		cfg.RequestLimits = proxyconfig.RequestLimitsConfig{
			MaxConcurrent:           1,
			MaxWebsocketConnections: 8,
		}
	})
	server.AttachWebsocketRoute("/v1/ws", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	holdStarted := make(chan struct{})
	holdRelease := make(chan struct{})
	server.engine.GET("/v1/hold", func(c *gin.Context) {
		close(holdStarted)
		<-holdRelease
		c.Status(http.StatusOK)
	})
	holdDone := make(chan struct{})
	go func() {
		defer close(holdDone)
		server.engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/hold", nil))
	}()
	<-holdStarted
	defer func() {
		close(holdRelease)
		<-holdDone
	}()

	serve := func(request *http.Request) int {
		recorder := httptest.NewRecorder()
		server.engine.ServeHTTP(recorder, request)
		return recorder.Code
	}
	upgradeRequest := func(method, path string) *http.Request {
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		return request
	}

	// Genuine upgrades are admitted by the independent websocket lane, so they
	// reach auth (401) or the attached relay stub (204) rather than queueing.
	for _, probe := range []struct {
		path string
		want int
	}{
		{"/v1/ws", http.StatusNoContent},
		{"/v1/responses", http.StatusUnauthorized},
		{"/backend-api/codex/responses", http.StatusUnauthorized},
		{"/v1/realtime", http.StatusUnauthorized},
		{"/v1/live/call-123", http.StatusUnauthorized},
		{"/v1/realtime/calls/call-123", http.StatusUnauthorized},
	} {
		if got := serve(upgradeRequest(http.MethodGet, probe.path)); got != probe.want {
			t.Errorf("GET %s upgrade status = %d, want %d", probe.path, got, probe.want)
		}
	}

	for _, probe := range []struct {
		name   string
		method string
		path   string
		header bool
	}{
		{"spoofed upgrade post to a websocket route", http.MethodPost, "/v1/responses", true},
		{"upgrade headers on a registered non-websocket route", http.MethodGet, "/v1/realtime/translations", true},
		{"upgrade headers on an unregistered route", http.MethodGet, "/v1/unregistered", true},
		{"plain get to a websocket route", http.MethodGet, "/v1/realtime", false},
	} {
		var request *http.Request
		if probe.header {
			request = upgradeRequest(probe.method, probe.path)
		} else {
			request = httptest.NewRequest(probe.method, probe.path, nil)
		}
		if got := serve(request); got != http.StatusTooManyRequests {
			t.Errorf("%s: status = %d, want %d", probe.name, got, http.StatusTooManyRequests)
		}
	}
}
