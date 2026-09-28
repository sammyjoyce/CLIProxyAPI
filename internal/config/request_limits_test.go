package config

import "testing"

// TestParseConfigBytesRequestLimits also keeps a retired max-concurrent-per-key
// line in the fixture to pin that unknown request-limits keys stay non-fatal for
// configs written before the per-key limiter was removed.
func TestParseConfigBytesRequestLimits(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
request-limits:
  max-concurrent: 96
  max-concurrent-per-key: 24
  max-websocket-connections: 128
  max-queued: 24
  queue-timeout-seconds: 2
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes returned error: %v", err)
	}

	if cfg.RequestLimits.MaxConcurrent != 96 {
		t.Fatalf("max concurrent = %d, want 96", cfg.RequestLimits.MaxConcurrent)
	}
	if cfg.RequestLimits.MaxWebsocketConnections != 128 {
		t.Fatalf("max websocket connections = %d, want 128", cfg.RequestLimits.MaxWebsocketConnections)
	}
	if cfg.RequestLimits.MaxQueued != 24 {
		t.Fatalf("max queued = %d, want 24", cfg.RequestLimits.MaxQueued)
	}
	if cfg.RequestLimits.QueueTimeoutSeconds != 2 {
		t.Fatalf("queue timeout seconds = %d, want 2", cfg.RequestLimits.QueueTimeoutSeconds)
	}
}
