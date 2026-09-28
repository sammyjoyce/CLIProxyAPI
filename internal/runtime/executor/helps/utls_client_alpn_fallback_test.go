package helps

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestUtlsRoundTripperFallsBackFromPooledH2 checks the gateway transport keeps
// pooled HTTP/2 for h2 servers and falls back to dedicated connections when
// ALPN selects HTTP/1.1 or nothing, without tripping the circuit breaker.
func TestUtlsRoundTripperFallsBackFromPooledH2(t *testing.T) {
	for _, protocol := range []string{"h2", "http/1.1", ""} {
		name := protocol
		if name == "" {
			name = "no-alpn"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("X-Proto", r.Proto)
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "echo:"+string(body))
			}))
			server.EnableHTTP2 = protocol == "h2"
			server.TLS = &stdtls.Config{NextProtos: []string{}}
			if protocol != "" {
				server.TLS.NextProtos = []string{protocol}
			}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())

			rt := newUtlsRoundTripperWithOptions("", utlsTransportOptions{
				connectTimeout:      5 * time.Second,
				tlsHandshakeTimeout: 5 * time.Second,
				breakerFailures:     1,
				breakerCooldown:     time.Minute,
			})
			rt.rootCAs = roots
			serverURL, _ := url.Parse(server.URL)
			wantMajor := "HTTP/1.1"
			if protocol == "h2" {
				wantMajor = "HTTP/2.0"
			}
			for i := 0; i < 3; i++ {
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL.String()+"/x", strings.NewReader("offer"))
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				body, _ := io.ReadAll(resp.Body)
				if errClose := resp.Body.Close(); errClose != nil {
					t.Fatalf("close body: %v", errClose)
				}
				if resp.StatusCode != http.StatusCreated || string(body) != "echo:offer" || resp.Header.Get("X-Proto") != wantMajor {
					t.Fatalf("request %d: status=%d body=%q proto=%q", i, resp.StatusCode, body, resp.Header.Get("X-Proto"))
				}
			}
			if errCircuit := rt.checkCircuit(serverURL.Hostname()); errCircuit != nil {
				t.Fatalf("ALPN fallback tripped circuit breaker: %v", errCircuit)
			}
			_, fallback := rt.http1Hosts.Load(serverURL.Host)
			if fallback != (protocol != "h2") {
				t.Fatalf("http1 fallback recorded = %v for protocol %q", fallback, protocol)
			}
		})
	}
}
