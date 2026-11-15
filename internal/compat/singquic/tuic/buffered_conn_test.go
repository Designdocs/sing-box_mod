package tuic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestBufferedConnOwnsPrefixAndPreservesStreamOrder(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	prefix := []byte("pre-read-")
	conn := newBufferedConn(raw, prefix)
	defer conn.Close()
	clear(prefix) // The handshake's pooled buffer is immediately reusable.
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	written := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("stream")); written <- err }()
	var got bytes.Buffer
	chunk := make([]byte, 3)
	for got.Len() < len("pre-read-stream") {
		n, err := conn.Read(chunk)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(chunk[:n])
	}
	if got.String() != "pre-read-stream" {
		t.Fatalf("prefix lost, duplicated or reordered: %q", got.String())
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

type observedReadConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func TestBufferedConnCloseUnblocksStreamRead(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	observed := &observedReadConn{Conn: raw, started: make(chan struct{})}
	conn := newBufferedConn(observed, []byte("x"))
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	<-observed.started
	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited for the blocked reader")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed stream read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake the blocked reader")
	}
}

func TestBufferedConnConcurrentReadsAndRevocation(t *testing.T) {
	for range 100 {
		raw, peer := net.Pipe()
		conn := newBufferedConn(raw, bytes.Repeat([]byte("payload"), 128))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				<-start
				for {
					if _, err := conn.Read(make([]byte, 1)); err != nil {
						return
					}
				}
			})
		}
		wg.Go(func() { <-start; _ = conn.Close() })
		wg.Go(func() { <-start; _ = conn.Close() })
		close(start)
		wg.Wait()
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("revoked connection returned cached data: %v", err)
		}
		peer.Close()
	}
}
