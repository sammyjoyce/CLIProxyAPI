package helps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func claudeTestTransport(t *testing.T, options utlsTransportOptions) *http.Transport {
	t.Helper()
	transport, ok := newClaudeCodeRoundTripper("", options).(*http.Transport)
	if !ok {
		t.Fatalf("Claude Code transport type = %T, want *http.Transport", newClaudeCodeRoundTripper("", options))
	}
	return transport
}

func TestClaudeCodeTransportBoundsIdleConnections(t *testing.T) {
	t.Parallel()

	transport := claudeTestTransport(t, utlsTransportOptions{})
	if transport.IdleConnTimeout != claudeCodeIdleConnTimeout {
		t.Fatalf("idle conn timeout = %s, want %s", transport.IdleConnTimeout, claudeCodeIdleConnTimeout)
	}
	if transport.MaxIdleConnsPerHost != claudeCodeMaxIdleConnsPerHost {
		t.Fatalf("max idle conns per host = %d, want %d", transport.MaxIdleConnsPerHost, claudeCodeMaxIdleConnsPerHost)
	}
}

func TestClaudeCodeTransportAppliesConnectTimeout(t *testing.T) {
	t.Parallel()

	transport := claudeTestTransport(t, utlsTransportOptions{connectTimeout: 10 * time.Millisecond})
	transport.DialTLSContext = newClaudeCodeBoundedDialer(contextAwareTestDialer{},
		utlsTransportOptions{connectTimeout: 10 * time.Millisecond}, newConnectionCircuitBreaker(0, 0))

	start := time.Now()
	_, err := transport.DialTLSContext(context.Background(), "tcp", "api.anthropic.com:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial took %s, want the connect timeout to bound it", elapsed)
	}
}

func TestClaudeCodeTransportCircuitBreakerFastFails(t *testing.T) {
	t.Parallel()

	breaker := newConnectionCircuitBreaker(2, time.Minute)
	dial := newClaudeCodeBoundedDialer(contextAwareTestDialer{},
		utlsTransportOptions{connectTimeout: time.Millisecond}, breaker)

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := dial(context.Background(), "tcp", "api.anthropic.com:443"); err == nil {
			t.Fatal("expected dial failure")
		}
	}
	_, err := dial(context.Background(), "tcp", "api.anthropic.com:443")
	if !errors.Is(err, errUtlsCircuitOpen) {
		t.Fatalf("dial error = %v, want errUtlsCircuitOpen", err)
	}
}

func TestClaudeCodeTransportIgnoresClientCancellationForCircuit(t *testing.T) {
	t.Parallel()

	breaker := newConnectionCircuitBreaker(1, time.Minute)
	dial := newClaudeCodeBoundedDialer(contextAwareTestDialer{}, utlsTransportOptions{}, breaker)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dial(ctx, "tcp", "api.anthropic.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want context.Canceled", err)
	}
	if err := breaker.checkCircuit("api.anthropic.com"); err != nil {
		t.Fatalf("client cancellation opened circuit: %v", err)
	}
}

func TestCachedClaudeCodeRoundTripperSeparatesTransportOptions(t *testing.T) {
	t.Parallel()

	const proxyURL = "http://127.0.0.1:29771"
	first := cachedClaudeCodeRoundTripper(proxyURL, utlsTransportOptions{connectTimeout: time.Second})
	same := cachedClaudeCodeRoundTripper(proxyURL, utlsTransportOptions{connectTimeout: time.Second})
	if first != same {
		t.Fatal("identical proxy and options returned different transports")
	}
	changed := cachedClaudeCodeRoundTripper(proxyURL, utlsTransportOptions{connectTimeout: 2 * time.Second})
	if first == changed {
		t.Fatal("changed outbound-transport options reused the previous transport")
	}
}

func TestConnectionCircuitBreakerFailureWindow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gap      time.Duration
		wantOpen bool
	}{
		{name: "within window", gap: time.Minute - time.Nanosecond, wantOpen: true},
		{name: "at boundary", gap: time.Minute},
		{name: "after window", gap: time.Minute + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			breaker := newConnectionCircuitBreaker(2, time.Minute)
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			breaker.nowFunc = func() time.Time { return now }
			breaker.recordConnectionFailure("upstream.invalid")
			now = now.Add(tc.gap)
			breaker.recordConnectionFailure("upstream.invalid")
			err := breaker.checkCircuit("upstream.invalid")
			if got := errors.Is(err, errUtlsCircuitOpen); got != tc.wantOpen {
				t.Fatalf("circuit open = %v, want %v after gap %s: %v", got, tc.wantOpen, tc.gap, err)
			}
			if errOther := breaker.checkCircuit("another.invalid"); errOther != nil {
				t.Fatalf("another host's circuit opened: %v", errOther)
			}
		})
	}
}

func TestConnectionCircuitBreakerReopensAfterCooldown(t *testing.T) {
	breaker := newConnectionCircuitBreaker(2, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	breaker.nowFunc = func() time.Time { return now }
	breaker.recordConnectionFailure("upstream.invalid")
	breaker.recordConnectionFailure("upstream.invalid")
	now = now.Add(time.Minute - time.Nanosecond)
	if err := breaker.checkCircuit("upstream.invalid"); !errors.Is(err, errUtlsCircuitOpen) {
		t.Fatalf("circuit closed before expiry: %v", err)
	}
	now = now.Add(time.Nanosecond)
	if err := breaker.checkCircuit("upstream.invalid"); err != nil {
		t.Fatalf("circuit still open at expiry: %v", err)
	}
	breaker.recordConnectionFailure("upstream.invalid")
	if err := breaker.checkCircuit("upstream.invalid"); err != nil {
		t.Fatalf("expired failures counted toward new threshold: %v", err)
	}
	breaker.recordConnectionFailure("upstream.invalid")
	if err := breaker.checkCircuit("upstream.invalid"); !errors.Is(err, errUtlsCircuitOpen) {
		t.Fatalf("circuit did not reopen at the new threshold: %v", err)
	}
	breaker.recordConnectionSuccess("upstream.invalid")
	if err := breaker.checkCircuit("upstream.invalid"); err != nil {
		t.Fatalf("success did not reset the circuit: %v", err)
	}
}

// Only Execute is used; embedding the interface makes unexpected execution paths
// fail rather than silently returning a successful stub result.
type circuitBreakerTestExecutor struct {
	cliproxyauth.ProviderExecutor
	client *http.Client
	url    string
}

func (*circuitBreakerTestExecutor) Identifier() string { return "circuit-breaker-test" }

func (e *circuitBreakerTestExecutor) Execute(ctx context.Context, _ *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	resp, err := e.client.Do(req)
	if resp != nil && resp.Body != nil {
		if errClose := resp.Body.Close(); err == nil {
			err = errClose
		}
	}
	return cliproxyexecutor.Response{}, err
}

func TestConnectionCircuitOpenDoesNotCooldownCredentials(t *testing.T) {
	for _, provider := range []string{"chrome", "claude"} {
		t.Run(provider, func(t *testing.T) {
			options := utlsTransportOptions{breakerFailures: 1, breakerCooldown: time.Minute, connectTimeout: time.Millisecond}
			host := "chatgpt.com"
			chrome := newUtlsRoundTripperWithOptions("", options)
			chrome.dialer = contextAwareTestDialer{}
			breaker := chrome.connectionCircuitBreaker
			var transport http.RoundTripper = chrome
			if provider == "claude" {
				host = "api.anthropic.com"
				claude := claudeTestTransport(t, options)
				claude.DialTLSContext = newClaudeCodeBoundedDialer(contextAwareTestDialer{}, options, breaker)
				transport = claude
				t.Cleanup(claude.CloseIdleConnections)
			}
			t.Cleanup(chrome.transport.CloseIdleConnections)
			breaker.recordConnectionFailure(host)
			executor := &circuitBreakerTestExecutor{client: &http.Client{Transport: transport}, url: "https://" + host + "/"}
			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.SetRetryConfig(0, 0, 2)
			manager.RegisterExecutor(executor)
			modelRegistry := registry.GetGlobalRegistry()
			model := "circuit-breaker-test-model"
			var authIDs []string
			for i := 0; i < 2; i++ {
				authID := fmt.Sprintf("%s-%d", t.Name(), i)
				authIDs = append(authIDs, authID)
				modelRegistry.RegisterClient(authID, executor.Identifier(), []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { modelRegistry.UnregisterClient(authID) })
				if _, err := manager.Register(t.Context(), &cliproxyauth.Auth{ID: authID, Provider: executor.Identifier()}); err != nil {
					t.Fatalf("register auth: %v", err)
				}
			}
			_, err := manager.Execute(t.Context(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			if !errors.Is(err, errUtlsCircuitOpen) {
				t.Fatalf("execution error = %v, want circuit-open cause", err)
			}
			for _, authID := range authIDs {
				auth, ok := manager.GetByID(authID)
				if !ok || auth.Failed != 1 {
					t.Fatalf("expected one failed attempt for %s, got %+v", authID, auth)
				}
				if auth.Unavailable || !auth.NextRetryAfter.IsZero() {
					t.Errorf("host circuit cooled credential %s", authID)
				}
				if state := auth.ModelStates[model]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
					t.Errorf("host circuit cooled model for %s: %+v", authID, state)
				}
			}
		})
	}
}
