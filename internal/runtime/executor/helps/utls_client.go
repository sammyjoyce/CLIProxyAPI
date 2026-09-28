package helps

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using a Chrome fingerprint for
// providers that require browser-like TLS. HTTP/2 connections are pooled and
// bounded by a shared HTTP/2 transport with establishment-only timeouts and a
// per-host circuit breaker. When ALPN selects HTTP/1.1 or nothing (for example
// behind a TLS-inspecting proxy), the host falls back to dedicated per-request
// connections that use the same dial bounds and close with the response body.
type utlsRoundTripper struct {
	*connectionCircuitBreaker
	dialer    proxy.Dialer
	transport *http2.Transport
	options   utlsTransportOptions
	// http1Hosts records authorities whose last handshake did not negotiate h2.
	http1Hosts sync.Map
	// rootCAs overrides system roots; tests only.
	rootCAs *x509.CertPool
}

// errUtlsNonH2Negotiated reports that the pooled HTTP/2 dial completed a TLS
// handshake but ALPN did not select h2. The HTTP/2 transport returns dial errors
// before reading the request, so the request can be sent on a dedicated
// connection instead. It is not a connectivity failure for the circuit breaker.
var errUtlsNonH2Negotiated = errors.New("utls: server did not negotiate h2")

type closeConnectionBody struct {
	io.ReadCloser
	closeConnection func() error
	once            sync.Once
	err             error
}

func (b *closeConnectionBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		var errConnection error
		if b.closeConnection != nil {
			errConnection = b.closeConnection()
		}
		var errBody error
		if b.ReadCloser != nil {
			errBody = b.ReadCloser.Close()
		}
		b.err = errors.Join(errBody, errConnection)
	})
	return b.err
}

type utlsTransportOptions struct {
	connectTimeout      time.Duration
	tlsHandshakeTimeout time.Duration
	breakerFailures     int
	breakerCooldown     time.Duration
}

func newUtlsRoundTripperWithOptions(proxyURL string, options utlsTransportOptions) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	roundTripper := &utlsRoundTripper{
		connectionCircuitBreaker: newConnectionCircuitBreaker(options.breakerFailures, options.breakerCooldown),
		dialer:                   dialer,
		options:                  options,
	}
	roundTripper.transport = &http2.Transport{
		DialTLSContext:             roundTripper.dialTLSContext,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout:            claudeCodeIdleConnTimeout,
	}
	return roundTripper
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := utlsAuthorityAddr(req)
	if _, http1 := t.http1Hosts.Load(addr); !http1 {
		resp, err := t.transport.RoundTrip(req)
		if err == nil || !errors.Is(err, errUtlsNonH2Negotiated) {
			return resp, err
		}
		t.http1Hosts.Store(addr, struct{}{})
	}
	return t.roundTripDedicated(req, addr)
}

// roundTripDedicated sends one request on its own bounded uTLS connection and
// follows whichever protocol ALPN selects.
func (t *utlsRoundTripper) roundTripDedicated(req *http.Request, addr string) (*http.Response, error) {
	conn, errDial := dialBoundedTLS(req.Context(), t.dialer, t.options, t.connectionCircuitBreaker, "tcp", addr, t.handshake(false))
	if errDial != nil {
		return nil, errDial
	}
	tlsConn := conn.(*tls.UConn)
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		// The authority speaks h2 again; later requests return to the pool.
		t.http1Hosts.Delete(addr)
	}
	return roundTripUtlsConnection(req, tlsConn)
}

func (t *utlsRoundTripper) dialTLSContext(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
	return dialBoundedTLS(ctx, t.dialer, t.options, t.connectionCircuitBreaker, network, addr, t.handshake(true))
}

func (t *utlsRoundTripper) handshake(requireH2 bool) tlsHandshakeFunc {
	return func(handshakeCtx context.Context, raw net.Conn, host string) (net.Conn, error) {
		tlsConn := tls.UClient(raw, &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2", "http/1.1"},
			RootCAs:    t.rootCAs,
		}, tls.HelloChrome_Auto)
		if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
			return nil, errHandshake
		}
		if protocol := tlsConn.ConnectionState().NegotiatedProtocol; requireH2 && protocol != "h2" {
			return nil, fmt.Errorf("%w (ALPN %q)", errUtlsNonH2Negotiated, protocol)
		}
		return tlsConn, nil
	}
}

func utlsAuthorityAddr(req *http.Request) string {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}

// roundTripUtlsConnection selects the HTTP protocol before sending the request.
// Empty ALPN is HTTP/1.1, including when a TLS-inspecting proxy omits ALPN.
func roundTripUtlsConnection(req *http.Request, tlsConn *tls.UConn) (*http.Response, error) {
	closeConnection := func() error {
		// The HTTP/1.1 transport may already have closed its non-pooled
		// connection after reading the response or canceling the request.
		if errClose := tlsConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
			return errClose
		}
		return nil
	}
	var resp *http.Response
	var err error
	switch protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol {
	case "h2":
		h2Conn, errClientConn := (&http2.Transport{}).NewClientConn(tlsConn)
		if errClientConn != nil {
			err = fmt.Errorf("utls: initialize HTTP/2 connection: %w", errClientConn)
			break
		}
		closeConnection = h2Conn.Close
		resp, err = h2Conn.RoundTrip(req)
	case "", "http/1.1":
		// Reuse the already-handshaken uTLS connection. A fresh, non-pooling
		// transport retains net/http's cancellation and request-body handling
		// without changing the TLS fingerprint or redialing through another path.
		transport := &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return tlsConn, nil
			},
		}
		resp, err = transport.RoundTrip(req)
		transport.CloseIdleConnections()
	default:
		err = fmt.Errorf("utls: unsupported negotiated protocol %q", protocol)
	}
	if err != nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after round trip failure: %v", errClose)
		}
		return nil, err
	}
	if resp == nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after empty response: %v", errClose)
		}
		return nil, fmt.Errorf("utls: upstream returned an empty response")
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &closeConnectionBody{
		ReadCloser:      resp.Body,
		closeConnection: closeConnection,
	}
	return resp, nil
}

func dialWithContext(ctx context.Context, dialer proxy.Dialer, network, addr string) (net.Conn, error) {
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("utls: dialer does not support context cancellation")
	}
	return contextDialer.DialContext(ctx, network, addr)
}

func shouldRecordConnectionFailure(parent context.Context, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, errUtlsNonH2Negotiated) {
		return false
	}
	return !errors.Is(err, context.DeadlineExceeded) || parent.Err() == nil
}

// claudeCodeSessionCacheCapacity bounds the per-transport TLS session cache for
// the Anthropic inference plane.
const claudeCodeSessionCacheCapacity = 32

// newClaudeCodeTLSConfig builds the uTLS config for one inference-plane dial.
//
// OmitEmptyPsk keeps the pre_shared_key extension silent until a session is
// cached, so an unresumed ClientHello stays byte-identical to the captured
// native handshake. PreferSkipResumptionOnNilExtension turns uTLS's HelloCustom
// "resume without the matching extension" panic into a skipped resumption.
func newClaudeCodeTLSConfig(host string, sessionCache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// claudeCodeTLSClientHelloSpec reproduces the deterministic Node/OpenSSL
// ClientHello emitted by Claude Code 2.1.220 on macOS arm64. Keep this spec in
// sync with a fresh native capture whenever the advertised Claude Code version
// changes.
func claudeCodeTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11), after
			// padding. It contributes zero bytes until a cached session exists.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

const claudeCodeRoundTripperCacheCapacity = 64

var claudeCodeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	claudeCodeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

var claudeCodeMessagesHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Timeout",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

var claudeCodeCountTokensHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

func claudeCodeRequestHeaderOrder(_, requestTarget string) []string {
	if strings.HasPrefix(requestTarget, "/v1/messages/count_tokens") {
		return claudeCodeCountTokensHeaderOrder
	}
	return claudeCodeMessagesHeaderOrder
}

func cachedClaudeCodeRoundTripper(proxyURL string, options utlsTransportOptions) http.RoundTripper {
	// Keying on the outbound-transport options as well as the proxy keeps a hot
	// reload from serving a transport that still carries the previous bounds.
	key := fmt.Sprintf("%s|%s|%s|%d|%s", proxyURL, options.connectTimeout, options.tlsHandshakeTimeout,
		options.breakerFailures, options.breakerCooldown)
	return claudeCodeRoundTripperCache.GetOrAdd(key, func() http.RoundTripper {
		return newClaudeCodeRoundTripper(proxyURL, options)
	})
}

func newClaudeCodeRoundTripper(proxyURL string, options utlsTransportOptions) http.RoundTripper {
	breaker := newConnectionCircuitBreaker(options.breakerFailures, options.breakerCooldown)
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("claude tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &http.Transport{
		ForceAttemptHTTP2:   false,
		DialTLSContext:      newClaudeCodeBoundedDialer(dialer, options, breaker),
		IdleConnTimeout:     claudeCodeIdleConnTimeout,
		MaxIdleConnsPerHost: claudeCodeMaxIdleConnsPerHost,
	}
}

// newClaudeCodeBoundedDialer performs the Claude Code TLS handshake under the
// outbound-transport bounds. The ClientHello and header ordering are unchanged;
// only connection establishment is bounded.
func newClaudeCodeBoundedDialer(
	dialer proxy.Dialer,
	options utlsTransportOptions,
	breaker *connectionCircuitBreaker,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	// The cache is scoped to this dialer, which is already keyed by proxy,
	// so resumption never crosses proxy boundaries.
	sessionCache := tls.NewLRUClientSessionCache(claudeCodeSessionCacheCapacity)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialBoundedTLS(ctx, dialer, options, breaker, network, addr,
			func(handshakeCtx context.Context, raw net.Conn, host string) (net.Conn, error) {
				tlsConn := tls.UClient(raw, newClaudeCodeTLSConfig(host, sessionCache), tls.HelloCustom)
				if errPreset := tlsConn.ApplyPreset(claudeCodeTLSClientHelloSpec()); errPreset != nil {
					return nil, fmt.Errorf("claude tls: apply Claude Code ClientHello: %w", errPreset)
				}
				if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
					return nil, fmt.Errorf("claude tls: handshake upstream: %w", errHandshake)
				}
				return httpwire.NewOrderedRequestConn(tlsConn, claudeCodeRequestHeaderOrder), nil
			})
	}
}

// fallbackRoundTripper uses provider-specific TLS fingerprints for protected
// HTTPS hosts and falls back to the standard transport for all other requests.
type fallbackRoundTripper struct {
	anthropic http.RoundTripper
	chrome    http.RoundTripper
	fallback  http.RoundTripper
}

type sharedTransportKey struct {
	proxyURL string
	options  utlsTransportOptions
}

var sharedProtectedTransports = internalcache.NewBoundedLRU[sharedTransportKey, *utlsRoundTripper](
	DefaultTransportCacheCapacity,
	func(_ sharedTransportKey, transport *utlsRoundTripper) {
		transport.transport.CloseIdleConnections()
	},
)

func sharedUtlsRoundTripper(proxyURL string, options utlsTransportOptions) http.RoundTripper {
	key := sharedTransportKey{proxyURL: proxyURL, options: options}
	return sharedProtectedTransports.GetOrAdd(key, func() *utlsRoundTripper {
		return newUtlsRoundTripperWithOptions(proxyURL, options)
	})
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if IsAnthropicUpstreamURL(req.URL) {
		return f.anthropic.RoundTrip(req)
	}
	if req.URL.Scheme == "https" && strings.EqualFold(req.URL.Hostname(), "chatgpt.com") {
		return f.chrome.RoundTrip(req)
	}
	return f.fallback.RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using provider-specific TLS
// fingerprints for protected hosts. It uses Claude Code's Node/OpenSSL profile
// for Anthropic and a Chrome profile for ChatGPT, with a standard-transport
// fallback for other hosts.
func NewUtlsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	proxyURL := effectiveProxyURL(ctx, cfg, auth)

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	options := utlsOptionsFromConfig(cfg)
	var chromeRT http.RoundTripper = sharedUtlsRoundTripper(proxyURL, options)
	var anthropicRT http.RoundTripper = cachedClaudeCodeRoundTripper(proxyURL, options)
	var standardTransport http.RoundTripper = http.DefaultTransport
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			standardTransport = transport
		}
	} else if ctxRoundTripper != nil {
		chromeRT = ctxRoundTripper
		anthropicRT = ctxRoundTripper
		standardTransport = ctxRoundTripper
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			anthropic: anthropicRT,
			chrome:    chromeRT,
			fallback:  standardTransport,
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}

func utlsOptionsFromConfig(cfg *config.Config) utlsTransportOptions {
	if cfg == nil {
		return utlsTransportOptions{}
	}
	return utlsTransportOptions{
		connectTimeout:      time.Duration(max(cfg.OutboundTransport.ConnectTimeoutSeconds, 0)) * time.Second,
		tlsHandshakeTimeout: time.Duration(max(cfg.OutboundTransport.TLSHandshakeTimeoutSeconds, 0)) * time.Second,
		breakerFailures:     max(cfg.OutboundTransport.CircuitBreakerFailures, 0),
		breakerCooldown:     time.Duration(max(cfg.OutboundTransport.CircuitBreakerCooldownSeconds, 0)) * time.Second,
	}
}
