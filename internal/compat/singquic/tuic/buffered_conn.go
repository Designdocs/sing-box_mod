package tuic

import (
	"bytes"
	"net"
	"sync"
)

// bufferedConn owns the small payload read together with the TUIC header.
// Revocation may close the connection while the router is consuming it;
// pooled CachedConn buffers cannot be read and released concurrently.
type bufferedConn struct {
	net.Conn
	access sync.Mutex
	buffer []byte
	closed bool
}

func newBufferedConn(conn net.Conn, prefix []byte) *bufferedConn {
	return &bufferedConn{Conn: conn, buffer: bytes.Clone(prefix)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, net.ErrClosed
	}
	if len(c.buffer) > 0 {
		n := copy(p, c.buffer)
		c.buffer = c.buffer[n:]
		if len(c.buffer) == 0 {
			c.buffer = nil
		}
		c.access.Unlock()
		return n, nil
	}
	c.access.Unlock()
	return c.Conn.Read(p)
}

func (c *bufferedConn) Close() error {
	c.access.Lock()
	c.closed = true
	c.buffer = nil
	c.access.Unlock()
	// Never hold access while closing or blocking on the underlying stream:
	// Close must wake a reader even when no payload has arrived.
	return c.Conn.Close()
}
