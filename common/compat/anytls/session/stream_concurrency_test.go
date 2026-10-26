package session

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func TestStreamConcurrentRemoteFINWriteAndClose(t *testing.T) {
	for range 64 {
		session := NewServerSession(discardConn{}, nil, nil, nil)
		stream := newStream(1, session)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			for range 100 {
				stream.Write([]byte("in-flight"))
			}
		})
		wg.Go(func() { <-start; stream.closeLocally() })
		wg.Go(func() { <-start; stream.Close() })
		close(start)
		wg.Wait()
		if _, err := stream.Write([]byte("closed")); err == nil {
			t.Fatal("write after close succeeded")
		}
		if _, err := stream.Read(make([]byte, 1)); err == nil {
			t.Fatal("read after close succeeded")
		}
	}
}
