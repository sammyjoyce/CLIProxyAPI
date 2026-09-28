package config

import "testing"

func TestParseConfigBytesOutboundTransport(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
outbound-transport:
  connect-timeout-seconds: 10
  tls-handshake-timeout-seconds: 7
  circuit-breaker-failures: 4
  circuit-breaker-cooldown-seconds: 11
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes returned error: %v", err)
	}

	if cfg.OutboundTransport.ConnectTimeoutSeconds != 10 {
		t.Fatalf("connect timeout seconds = %d, want 10", cfg.OutboundTransport.ConnectTimeoutSeconds)
	}
	if cfg.OutboundTransport.TLSHandshakeTimeoutSeconds != 7 {
		t.Fatalf("TLS handshake timeout seconds = %d, want 7", cfg.OutboundTransport.TLSHandshakeTimeoutSeconds)
	}
	if cfg.OutboundTransport.CircuitBreakerFailures != 4 {
		t.Fatalf("circuit breaker failures = %d, want 4", cfg.OutboundTransport.CircuitBreakerFailures)
	}
	if cfg.OutboundTransport.CircuitBreakerCooldownSeconds != 11 {
		t.Fatalf("circuit breaker cooldown seconds = %d, want 11", cfg.OutboundTransport.CircuitBreakerCooldownSeconds)
	}
}
