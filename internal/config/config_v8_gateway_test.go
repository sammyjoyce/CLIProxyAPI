package config_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

const gatewayLegacyYAML = `request-limits:
  max-concurrent: 96
  max-websocket-connections: 128
  max-queued: 24
  queue-timeout-seconds: 2
outbound-transport:
  connect-timeout-seconds: 10
  tls-handshake-timeout-seconds: 7
  circuit-breaker-failures: 4
  circuit-breaker-cooldown-seconds: 11
`

const gatewayV8YAML = `server:
  request-limits:
    max-concurrent: 96
    max-websocket-connections: 128
    max-queued: 24
    queue-timeout-seconds: 2
requests:
  outbound-transport:
    connect-timeout-seconds: 10
    tls-handshake-timeout-seconds: 7
    circuit-breaker-failures: 4
    circuit-breaker-cooldown-seconds: 11
`

const gatewayV8ZerosYAML = `server:
  request-limits:
    max-concurrent: 0
    max-websocket-connections: 0
    max-queued: 0
    queue-timeout-seconds: 0
requests:
  outbound-transport:
    connect-timeout-seconds: 0
    tls-handshake-timeout-seconds: 0
    circuit-breaker-failures: 0
    circuit-breaker-cooldown-seconds: 0
`

type gatewaySettings struct {
	limits    config.RequestLimitsConfig
	transport config.OutboundTransportConfig
}

func configuredGateway() gatewaySettings {
	return gatewaySettings{
		limits: config.RequestLimitsConfig{
			MaxConcurrent: 96, MaxWebsocketConnections: 128, MaxQueued: 24, QueueTimeoutSeconds: 2,
		},
		transport: config.OutboundTransportConfig{
			ConnectTimeoutSeconds: 10, TLSHandshakeTimeoutSeconds: 7,
			CircuitBreakerFailures: 4, CircuitBreakerCooldownSeconds: 11,
		},
	}
}

func assertGatewaySettings(t *testing.T, cfg *config.Config, want gatewaySettings) {
	t.Helper()
	if cfg.RequestLimits != want.limits || cfg.OutboundTransport != want.transport {
		t.Fatalf("gateway settings changed: limits=%+v transport=%+v; want limits=%+v transport=%+v",
			cfg.RequestLimits, cfg.OutboundTransport, want.limits, want.transport)
	}
}

func gatewayLayout(t *testing.T, data []byte, v8 bool) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for legacy, section := range map[string]string{"request-limits": "server", "outbound-transport": "requests"} {
		_, oldPresent := doc[legacy]
		nested, _ := doc[section].(map[string]any)
		_, newPresent := nested[legacy]
		if oldPresent == v8 || newPresent != v8 {
			t.Fatalf("wrong layout for %s: legacy=%v v8=%v; want v8=%v\n%s", legacy, oldPresent, newPresent, v8, data)
		}
	}
}

func readGatewayConfig(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestV8GatewayLoadPresencePrecedence(t *testing.T) {
	partial := configuredGateway()
	partial.limits.MaxConcurrent = 0
	partial.limits.MaxWebsocketConnections = 0
	partial.transport.ConnectTimeoutSeconds = 0
	partial.transport.CircuitBreakerFailures = 0
	const partialV8 = "server: {request-limits: {max-concurrent: 0, max-websocket-connections: 0}}\nrequests: {outbound-transport: {connect-timeout-seconds: 0, circuit-breaker-failures: 0}}\n"
	for _, tc := range []struct {
		name, raw string
		want      gatewaySettings
		cleanup   bool
	}{
		{"legacy", gatewayLegacyYAML, configuredGateway(), false},
		{"version marker alone", "config-version: 8\n" + gatewayLegacyYAML, configuredGateway(), false},
		{"v8", gatewayV8YAML, configuredGateway(), false},
		{"v8 zeros", gatewayV8ZerosYAML, gatewaySettings{}, false},
		{"partial v8 zeros", gatewayLegacyYAML + partialV8, partial, true},
		{"v8 before legacy", partialV8 + gatewayLegacyYAML, partial, true},
		{"all v8 zeros override legacy", gatewayLegacyYAML + gatewayV8ZerosYAML, gatewaySettings{}, true},
		{"empty v8 maps do not erase legacy leaves", gatewayLegacyYAML + "server: {request-limits: {}}\nrequests: {outbound-transport: {}}\n", configuredGateway(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.ParseConfigBytes([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			assertGatewaySettings(t, cfg, tc.want)
			normalized, changed, err := config.NormalizeConfigLayout([]byte(tc.raw), false)
			if err != nil || changed != tc.cleanup {
				t.Fatalf("normalize without migration: changed=%v error=%v", changed, err)
			}
			if !changed && string(normalized) != tc.raw {
				t.Fatal("unchanged layout was rewritten")
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err = os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			assertGatewaySettings(t, loaded, tc.want)
			if got := readGatewayConfig(t, path); string(got) != string(normalized) {
				t.Fatalf("load did not apply only conflict cleanup:\n%s", got)
			}
			if _, changed, err = config.NormalizeConfigLayout(normalized, false); err != nil || changed {
				t.Fatalf("conflicting fields remain after cleanup: changed=%v error=%v", changed, err)
			}
		})
	}
}

func TestV8GatewayMigrationAndSave(t *testing.T) {
	partial := configuredGateway()
	partial.limits.MaxQueued = 0
	partial.transport.CircuitBreakerCooldownSeconds = 0
	for _, tc := range []struct {
		name, raw string
		want      gatewaySettings
	}{
		{"legacy", gatewayLegacyYAML, configuredGateway()},
		{"retired per-key limit", strings.Replace(gatewayLegacyYAML, "request-limits:\n", "request-limits:\n  max-concurrent-per-key: 24\n", 1), configuredGateway()},
		{"v8", gatewayV8YAML, configuredGateway()},
		{"partially migrated", gatewayLegacyYAML + "server: {request-limits: {max-queued: 0}}\nrequests: {outbound-transport: {circuit-breaker-cooldown-seconds: 0}}\n", partial},
		{"mixed zeros", gatewayLegacyYAML + gatewayV8ZerosYAML, gatewaySettings{}},
		{"empty legacy structs", "request-limits: {}\noutbound-transport: {}\n", gatewaySettings{}},
		{"null legacy structs", "request-limits: null\noutbound-transport: null\n", gatewaySettings{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			migrated, changed, err := config.NormalizeConfigLayout([]byte(tc.raw), true)
			if err != nil || !changed {
				t.Fatalf("migration: changed=%v error=%v", changed, err)
			}
			gatewayLayout(t, migrated, true)
			if err = config.ValidateV8Config(migrated); err != nil {
				t.Fatalf("migrated layout is invalid: %v", err)
			}
			cfg, err := config.ParseConfigBytes(migrated)
			if err != nil {
				t.Fatal(err)
			}
			assertGatewaySettings(t, cfg, tc.want)

			// Exercise the direct legacy-save migration as well as normalization.
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err = os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			for _, migrate := range []bool{true, false, true} {
				if err = config.SaveConfigPreserveComments(path, cfg, migrate); err != nil {
					t.Fatal(err)
				}
				saved := readGatewayConfig(t, path)
				gatewayLayout(t, saved, true)
				if err = config.ValidateV8Config(saved); err != nil {
					t.Fatalf("saved layout is invalid: %v", err)
				}
				cfg, err = config.LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				assertGatewaySettings(t, cfg, tc.want)
			}
		})
	}
}

func TestV8GatewaySavePreservesLayoutAndZeroUpdates(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		v8        bool
	}{
		{"legacy", gatewayLegacyYAML, false},
		{"v8", gatewayV8YAML, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []gatewaySettings{configuredGateway(), {}, configuredGateway()} {
				cfg.RequestLimits, cfg.OutboundTransport = want.limits, want.transport
				if err = config.SaveConfigPreserveComments(path, cfg); err != nil {
					t.Fatal(err)
				}
				saved := readGatewayConfig(t, path)
				gatewayLayout(t, saved, tc.v8)
				cfg, err = config.LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				assertGatewaySettings(t, cfg, want)
			}
		})
	}
}

func TestV8GatewayValidation(t *testing.T) {
	for _, raw := range []string{
		gatewayV8YAML, gatewayV8ZerosYAML,
		"server: {request-limits: {}}\nrequests: {outbound-transport: {}}",
	} {
		if err := config.ValidateV8Config([]byte(raw)); err != nil {
			t.Errorf("rejected v8 safeguards: %v", err)
		}
	}
	for _, raw := range []string{
		gatewayLegacyYAML, gatewayLegacyYAML + gatewayV8YAML,
		"request-limits: {}", "outbound-transport: {}",
		"server: {request-limits: false}", "requests: {outbound-transport: []}",
		"server: {request-limits: {max-concurrent: invalid}}",
		"requests: {outbound-transport: {connect-timeout-seconds: invalid}}",
		"server: {request-limits: {max-concurent: 4}}",
		"requests: {outbound-transport: {connection-timeout-seconds: 10}}",
	} {
		if err := config.ValidateV8Config([]byte(raw)); err == nil {
			t.Errorf("accepted invalid v8 safeguards: %s", raw)
		}
	}
}

// Keep the management regression here so the gateway mapping, migration and API
// write contract are tested together without changing management implementation.
func TestV8GatewayManagementPatchPreservesSafeguards(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "debug: false\n" + strings.Replace(gatewayLegacyYAML, "  max-concurrent:", "  # Preserve gateway safeguards\n  max-concurrent:", 1)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, nil)
	reloads := make(chan *config.Config, 1)
	h.SetConfigReloadHook(func(_ context.Context, snapshot *config.Config) { reloads <- snapshot })
	router := gin.New()
	router.GET("/v8/management/config", h.ConfigV8)
	router.PATCH("/v8/management/config", h.ConfigV8)
	router.PATCH("/v8/management/config/*path", h.ConfigV8)
	router.PUT("/v0/management/debug", h.PutDebug)
	request := func(method, url, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(method, url, strings.NewReader(body)))
		if response.Code != status {
			t.Fatalf("%s %s: status=%d body=%s", method, url, response.Code, response.Body.String())
		}
		return response
	}
	assertSaved := func(want gatewaySettings) {
		t.Helper()
		saved := readGatewayConfig(t, path)
		gatewayLayout(t, saved, true)
		if err := config.ValidateV8Config(saved); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(saved), "# Preserve gateway safeguards") {
			t.Fatal("save lost the gateway comment")
		}
		loaded, err := config.LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		assertGatewaySettings(t, loaded, want)
		select {
		case snapshot := <-reloads:
			assertGatewaySettings(t, snapshot, want)
		case <-time.After(5 * time.Second):
			t.Fatal("missing management reload snapshot")
		}
	}
	response := request(http.MethodGet, "/v8/management/config", "", http.StatusOK)
	view, err := config.ParseConfigBytes(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertGatewaySettings(t, view, configuredGateway())
	if got := string(readGatewayConfig(t, path)); got != raw {
		t.Fatal("GET migrated the file")
	}
	request(http.MethodPatch, "/v8/management/config", `{"server":{"port":8318}}`, http.StatusOK)
	assertSaved(configuredGateway())

	want := configuredGateway()
	want.limits.MaxConcurrent = 0
	request(http.MethodPatch, "/v8/management/config/server/request-limits", `{"max-concurrent":0}`, http.StatusOK)
	assertSaved(want)
	want.transport.ConnectTimeoutSeconds = 0
	request(http.MethodPatch, "/v8/management/config/requests/outbound-transport", `{"connect-timeout-seconds":0}`, http.StatusOK)
	assertSaved(want)

	before := string(readGatewayConfig(t, path))
	request(http.MethodPatch, "/v8/management/config", `{"server":{"request-limits":{"unknown-limit":1}}}`, http.StatusBadRequest)
	if got := string(readGatewayConfig(t, path)); got != before {
		t.Fatal("invalid patch changed the persisted safeguards")
	}
	request(http.MethodPut, "/v0/management/debug", `{"value":true}`, http.StatusOK)
	assertSaved(want)
}
