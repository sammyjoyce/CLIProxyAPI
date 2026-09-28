package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// RequestLimitOptions configures concurrent request admission.
type RequestLimitOptions struct {
	MaxConcurrent           int
	MaxWebsocketConnections int
	MaxQueued               int
	QueueTimeout            time.Duration

	// WebsocketRoute reports whether a route pattern resolved by the router is
	// registered as a downstream websocket upgrade endpoint. The dedicated
	// websocket lane admits a request only when this reports true for the route
	// the router actually matched, so unregistered paths and non-upgrade
	// requests can never take a websocket permit.
	WebsocketRoute func(pattern string) bool
}

// RequestLimiter bounds active and queued proxy requests.
type RequestLimiter struct {
	global    chan struct{}
	websocket chan struct{}
	queue     chan struct{}
	options   RequestLimitOptions
}

// NewRequestLimiter returns middleware that rejects excess work before later
// middleware or handlers read and retain the request body.
func NewRequestLimiter(options RequestLimitOptions) *RequestLimiter {
	limiter := &RequestLimiter{options: options}
	if options.MaxConcurrent > 0 {
		limiter.global = make(chan struct{}, options.MaxConcurrent)
	}
	if options.MaxWebsocketConnections > 0 {
		limiter.websocket = make(chan struct{}, options.MaxWebsocketConnections)
	}
	if options.MaxQueued > 0 {
		limiter.queue = make(chan struct{}, options.MaxQueued)
	}
	return limiter
}

// Middleware returns the Gin admission middleware.
func (limiter *RequestLimiter) Middleware() gin.HandlerFunc {
	options := limiter.options
	return func(c *gin.Context) {
		if limiter.websocket != nil && isWebsocketUpgradeRequest(c, options.WebsocketRoute) {
			select {
			case limiter.websocket <- struct{}{}:
				defer func() { <-limiter.websocket }()
				c.Next()
			default:
				rejectOverloaded(c)
			}
			return
		}
		if limiter.global == nil {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		var cancel context.CancelFunc
		if options.QueueTimeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, options.QueueTimeout)
			defer cancel()
		}

		select {
		case limiter.global <- struct{}{}:
		default:
			if limiter.queue == nil {
				rejectOverloaded(c)
				return
			}
			select {
			case limiter.queue <- struct{}{}:
			default:
				rejectOverloaded(c)
				return
			}
			select {
			case limiter.global <- struct{}{}:
				<-limiter.queue
			case <-ctx.Done():
				<-limiter.queue
				rejectOverloaded(c)
				return
			}
		}
		defer func() { <-limiter.global }()
		c.Next()
	}
}

// isWebsocketUpgradeRequest reports whether c is eligible for the dedicated
// WebSocket semaphore: an HTTP GET that Gorilla recognizes as a WebSocket
// upgrade and whose router-resolved route pattern is registered as a websocket
// upgrade endpoint. The pattern comes from the router, so parameterized
// endpoints match exactly and a plain GET, an unregistered path, or an upgrade
// header on another method all use the ordinary global/queue limiter path.
func isWebsocketUpgradeRequest(c *gin.Context, isWebsocketRoute func(pattern string) bool) bool {
	if c == nil || c.Request == nil || c.Request.Method != http.MethodGet {
		return false
	}
	if !websocket.IsWebSocketUpgrade(c.Request) {
		return false
	}
	if isWebsocketRoute == nil {
		return false
	}
	return isWebsocketRoute(c.FullPath())
}

// Queued returns the current number of requests waiting for capacity.
func (limiter *RequestLimiter) Queued() int {
	if limiter == nil {
		return 0
	}
	return len(limiter.queue)
}

func rejectOverloaded(c *gin.Context) {
	c.Header("Retry-After", "1")
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error": gin.H{
			"message": "server is at request capacity; retry later",
			"type":    "server_overloaded",
		},
	})
}
