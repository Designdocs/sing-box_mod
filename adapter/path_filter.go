package adapter

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
)

type pathFilterKey struct{}

func WithPathFilter(ctx context.Context, filter func(*http.Request) bool) context.Context {
	return context.WithValue(ctx, pathFilterKey{}, filter)
}

func WithFilteredHTTPFallback(ctx context.Context, next http.Handler) http.Handler {
	filter, _ := ctx.Value(pathFilterKey{}).(func(*http.Request) bool)
	if filter == nil {
		return next
	}
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filter(r) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RejectProbe(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	filter, _ := ctx.Value(pathFilterKey{}).(func(*http.Request) bool)
	if filter == nil || !filter(r) {
		return false
	}
	w.WriteHeader(http.StatusNotFound)
	return true
}

type RejectedStreamFilter func(net.Conn, []byte, io.Reader) bool
type rejectedStreamKey struct{}

func WithRejectedStreamFilter(ctx context.Context, f RejectedStreamFilter) context.Context {
	return context.WithValue(ctx, rejectedStreamKey{}, f)
}

func RejectedStreamFilterFrom(ctx context.Context) RejectedStreamFilter {
	f, _ := ctx.Value(rejectedStreamKey{}).(RejectedStreamFilter)
	return f
}

// HandshakePrefixConn remembers only a possible HTTP request line from the
// native protocol's first read. The caller consults it only on handshake error.
type HandshakePrefixConn struct {
	net.Conn
	Prefix []byte
	read   bool
}

func (c *HandshakePrefixConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.read && n > 0 {
		c.read = true
		first := p[:min(n, 8192)]
		for _, method := range [...]string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "} {
			size := min(len(first), len(method))
			if string(first[:size]) != method[:size] {
				continue
			}
			if end := bytes.IndexByte(first, '\n'); end >= 0 {
				first = first[:end+1]
			}
			c.Prefix = bytes.Clone(first)
			break
		}
	}
	return n, err
}
func (c *HandshakePrefixConn) Upstream() any           { return c.Conn }
func (c *HandshakePrefixConn) ReaderReplaceable() bool { return c.read }
func (c *HandshakePrefixConn) WriterReplaceable() bool { return true }

type inboundListenerWrapperKey struct{}

func WithInboundListenerWrapper(ctx context.Context, f func(net.Listener) (net.Listener, error)) context.Context {
	return context.WithValue(ctx, inboundListenerWrapperKey{}, f)
}
func WrapInboundListener(ctx context.Context, l net.Listener) (net.Listener, error) {
	if f, ok := ctx.Value(inboundListenerWrapperKey{}).(func(net.Listener) (net.Listener, error)); ok {
		return f(l)
	}
	return l, nil
}
