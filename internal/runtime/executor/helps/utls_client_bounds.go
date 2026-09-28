package helps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// claudeCodeIdleConnTimeout matches the Chrome transport's idle bound so Anthropic
// connections cannot be retained indefinitely.
const claudeCodeIdleConnTimeout = 90 * time.Second

// claudeCodeMaxIdleConnsPerHost keeps HTTP/1.1 connections warm for the dominant
// upstream. Go's default of 2 forces a fresh TCP and TLS handshake for nearly every
// concurrent request once the proxy is under load.
const claudeCodeMaxIdleConnsPerHost = 64

type circuitBreakerState struct {
	failures    int
	lastFailure time.Time
	openUntil   time.Time
}

var errUtlsCircuitOpen = errors.New("utls: provider connection circuit is open")

// connectionCircuitBreaker fails connection establishment fast while an upstream
// host is repeatedly unreachable, so callers do not occupy request permits waiting
// on dials that cannot succeed.
type connectionCircuitBreaker struct {
	breakerFailures int
	breakerCooldown time.Duration
	breakerMu       sync.Mutex
	breakers        map[string]circuitBreakerState
	nowFunc         func() time.Time
}

func newConnectionCircuitBreaker(failures int, cooldown time.Duration) *connectionCircuitBreaker {
	return &connectionCircuitBreaker{
		breakerFailures: max(failures, 0),
		breakerCooldown: cooldown,
		breakers:        make(map[string]circuitBreakerState),
		nowFunc:         time.Now,
	}
}

func (t *connectionCircuitBreaker) checkCircuit(host string) error {
	if t.breakerFailures <= 0 || t.breakerCooldown <= 0 {
		return nil
	}
	t.breakerMu.Lock()
	defer t.breakerMu.Unlock()
	state := t.breakers[host]
	if state.openUntil.After(t.nowFunc()) {
		// A host-level fast failure is not evidence against the selected credential.
		return cliproxyauth.WithCause(&cliproxyauth.Error{
			Code:    cliproxyauth.ErrorCodeConnectionLifecycle,
			Message: fmt.Sprintf("%s for %s until %s", errUtlsCircuitOpen, host, state.openUntil.Format(time.RFC3339)),
		}, errUtlsCircuitOpen)
	}
	if !state.openUntil.IsZero() {
		delete(t.breakers, host)
	}
	return nil
}

func (t *connectionCircuitBreaker) recordConnectionFailure(host string) {
	if t.breakerFailures <= 0 || t.breakerCooldown <= 0 {
		return
	}
	t.breakerMu.Lock()
	state := t.breakers[host]
	// Strip the monotonic reading so host suspend counts against both the quiet
	// period and the cooldown, matching the quota-cooldown idiom upstream uses.
	now := t.nowFunc().Round(0)
	if now.Sub(state.lastFailure) >= t.breakerCooldown {
		state = circuitBreakerState{}
	}
	state.failures++
	state.lastFailure = now
	if state.failures >= t.breakerFailures {
		state.openUntil = now.Add(t.breakerCooldown)
	}
	t.breakers[host] = state
	t.breakerMu.Unlock()
}

func (t *connectionCircuitBreaker) recordConnectionSuccess(host string) {
	t.breakerMu.Lock()
	delete(t.breakers, host)
	t.breakerMu.Unlock()
}

// tlsHandshakeFunc completes the provider-specific TLS handshake over an established
// connection. Implementations own their ClientHello and must not close raw on error.
type tlsHandshakeFunc func(ctx context.Context, raw net.Conn, host string) (net.Conn, error)

// dialBoundedTLS establishes a TLS connection under the outbound-transport bounds:
// a circuit-breaker check, an establishment-only connect timeout, and an
// establishment-only handshake timeout. Both timeouts end once the connection is
// established, so streaming responses remain unbounded.
func dialBoundedTLS(
	ctx context.Context,
	dialer proxy.Dialer,
	options utlsTransportOptions,
	breaker *connectionCircuitBreaker,
	network, addr string,
	handshake tlsHandshakeFunc,
) (net.Conn, error) {
	host, _, errSplit := net.SplitHostPort(addr)
	if errSplit != nil {
		host = addr
	}
	if errCircuit := breaker.checkCircuit(host); errCircuit != nil {
		return nil, errCircuit
	}

	dialCtx := ctx
	var cancelDial context.CancelFunc
	if options.connectTimeout > 0 {
		dialCtx, cancelDial = context.WithTimeout(ctx, options.connectTimeout)
		defer cancelDial()
	}
	rawConn, errDial := dialWithContext(dialCtx, dialer, network, addr)
	if errDial != nil {
		if shouldRecordConnectionFailure(ctx, errDial) {
			breaker.recordConnectionFailure(host)
		}
		return nil, errDial
	}

	handshakeCtx := ctx
	var cancelHandshake context.CancelFunc
	if options.tlsHandshakeTimeout > 0 {
		handshakeCtx, cancelHandshake = context.WithTimeout(ctx, options.tlsHandshakeTimeout)
		defer cancelHandshake()
	}
	tlsConn, errHandshake := handshake(handshakeCtx, rawConn, host)
	if errHandshake != nil {
		if errClose := rawConn.Close(); errClose != nil {
			log.Debugf("utls: close failed after TLS handshake error: %v", errClose)
		}
		if shouldRecordConnectionFailure(ctx, errHandshake) {
			breaker.recordConnectionFailure(host)
		}
		return nil, errHandshake
	}

	breaker.recordConnectionSuccess(host)
	return tlsConn, nil
}
