package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newTestInbound(t *testing.T) *Inbound {
	t.Helper()
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.AnyTLSInboundOptions{
		Users: []option.AnyTLSUser{{Name: "test-user", Password: "test-password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*Inbound)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func connectionCount(h *Inbound) int {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	return len(h.userconns)
}

func waitConnection(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not return")
	}
}

type readStartedConn struct {
	net.Conn
	reading chan struct{}
}

func (c *readStartedConn) Read(p []byte) (int, error) {
	select {
	case c.reading <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func TestInboundReleasesFinishedSessions(t *testing.T) {
	h := newTestInbound(t)
	var closed atomic.Int32
	for range 32 {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			h.NewConnectionEx(context.Background(), server, adapter.InboundContext{}, func(error) { closed.Add(1) })
			close(done)
		}()
		password := sha256.Sum256([]byte("test-password"))
		if _, err := client.Write(append(password[:], 0, 0)); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		waitConnection(t, done)
	}
	if count := connectionCount(h); count != 0 {
		t.Errorf("finished sessions retained: %d", count)
	}
	if count := closed.Load(); count != 32 {
		t.Errorf("close callbacks = %d, want 32", count)
	}
}

func TestInboundCloseStopsPendingConnections(t *testing.T) {
	h := newTestInbound(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	conn := &readStartedConn{Conn: server, reading: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), conn, adapter.InboundContext{}, nil)
		close(done)
	}()
	select {
	case <-conn.reading:
	case <-time.After(time.Second):
		t.Fatal("authentication did not start")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	waitConnection(t, done)
	if count := connectionCount(h); count != 0 {
		t.Fatalf("connections retained after close: %d", count)
	}
}

func writeFrame(t *testing.T, conn net.Conn, command byte, id uint32, data []byte) {
	t.Helper()
	frame := make([]byte, 7+len(data))
	frame[0] = command
	binary.BigEndian.PutUint32(frame[1:5], id)
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
	copy(frame[7:], data)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func nextFrame(t *testing.T, conn net.Conn, command byte, id uint32) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		var header [7]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
			t.Fatal(err)
		}
		if header[0] == command && binary.BigEndian.Uint32(header[1:5]) == id {
			return
		}
	}
}

type closingStreamHandler struct{}

func (closingStreamHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func TestInboundFailedAndFinishedStreamsKeepSessionReusable(t *testing.T) {
	h := newTestInbound(t)
	h.service.handler = closingStreamHandler{}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	var closed atomic.Int32
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), server, adapter.InboundContext{}, func(error) { closed.Add(1) })
		close(done)
	}()
	if err := client.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	password := sha256.Sum256([]byte("test-password"))
	if _, err := client.Write(append(password[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	writeFrame(t, client, 4, 0, []byte("v=1\npadding-md5="+h.service.padding.Load().Md5))
	writeFrame(t, client, 1, 1, nil)
	// The trailing byte makes the original pipe write wait for a reader that exited.
	writeFrame(t, client, 2, 1, []byte{0xff, 0})
	nextFrame(t, client, 3, 1)
	writeFrame(t, client, 8, 0, nil)
	nextFrame(t, client, 9, 0)
	writeFrame(t, client, 1, 2, nil)
	writeFrame(t, client, 2, 2, []byte{1, 127, 0, 0, 1, 0, 80})
	nextFrame(t, client, 3, 2)
	if count := connectionCount(h); count != 1 {
		t.Errorf("active session connections = %d, want 1", count)
	}
	if count := closed.Load(); count != 0 {
		t.Errorf("session callback ran after stream close: %d", count)
	}
	writeFrame(t, client, 8, 0, nil)
	nextFrame(t, client, 9, 0)
	_ = client.Close()
	waitConnection(t, done)
	if count := connectionCount(h); count != 0 {
		t.Errorf("finished session connections = %d", count)
	}
	if count := closed.Load(); count != 1 {
		t.Errorf("session close callbacks = %d, want 1", count)
	}
}

func TestInboundRejectsAuthenticationAfterUserRemoval(t *testing.T) {
	h := newTestInbound(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	connection := &inboundConnection{conn: server, cancel: cancel}
	h.userconns[server] = connection
	authenticating := make(chan struct{})
	resume := make(chan struct{})
	var resumeOnce sync.Once
	resumeAuthentication := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(resumeAuthentication)
	done := make(chan error, 1)
	go func() {
		done <- h.service.NewConnection(ctx, server, M.Socksaddr{}, nil, func(user string, password [32]byte) bool {
			close(authenticating)
			<-resume
			return h.authenticate(connection, user, password)
		})
	}()
	password := sha256.Sum256([]byte("test-password"))
	if _, err := client.Write(append(password[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-authenticating:
	case err := <-done:
		t.Fatalf("authentication exited before validation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("authentication did not reach validation")
	}
	if err := h.DelUsers([]string{"test-user"}); err != nil {
		t.Fatal(err)
	}
	resumeAuthentication()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("removed user authenticated from a stale snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("removed user's authentication did not exit")
	}
}

func TestInboundCancellationStopsAuthentication(t *testing.T) {
	h := newTestInbound(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	conn := &readStartedConn{Conn: server, reading: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(ctx, conn, adapter.InboundContext{}, nil)
		close(done)
	}()
	select {
	case <-conn.reading:
	case <-time.After(time.Second):
		t.Fatal("authentication did not start")
	}
	cancel()
	waitConnection(t, done)
	if count := connectionCount(h); count != 0 {
		t.Fatalf("canceled connections retained: %d", count)
	}
}

type unreadStreamHandler struct {
	entered chan struct{}
}

func (h unreadStreamHandler) NewConnectionEx(_ context.Context, _ net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	close(h.entered)
}

func TestInboundCloseUnblocksBackpressuredSession(t *testing.T) {
	h := newTestInbound(t)
	entered := make(chan struct{})
	h.service.handler = unreadStreamHandler{entered: entered}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), server, adapter.InboundContext{}, nil)
		close(done)
	}()
	if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	password := sha256.Sum256([]byte("test-password"))
	if _, err := client.Write(append(password[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	writeFrame(t, client, 4, 0, []byte("v=1\npadding-md5="+h.service.padding.Load().Md5))
	writeFrame(t, client, 1, 1, nil)
	writeFrame(t, client, 2, 1, []byte{1, 127, 0, 0, 1, 0, 80, 1})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("stream was not dispatched")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	waitConnection(t, done)
}

func TestInboundUserRemovalClosesAuthenticatedSession(t *testing.T) {
	h := newTestInbound(t)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	conn := &readStartedConn{Conn: server, reading: make(chan struct{}, 2)}
	var closed atomic.Int32
	done := make(chan struct{})
	go func() {
		h.NewConnectionEx(context.Background(), conn, adapter.InboundContext{}, func(error) { closed.Add(1) })
		close(done)
	}()
	if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	password := sha256.Sum256([]byte("test-password"))
	if _, err := client.Write(append(password[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
	// The second transport read starts only after authentication has committed.
	for range 2 {
		select {
		case <-conn.reading:
		case <-time.After(time.Second):
			t.Fatal("session did not finish authentication")
		}
	}
	if err := h.DelUsers([]string{"test-user"}); err != nil {
		t.Fatal(err)
	}
	waitConnection(t, done)
	if count := connectionCount(h); count != 0 {
		t.Errorf("removed user's sessions retained: %d", count)
	}
	if count := closed.Load(); count != 1 {
		t.Errorf("removed user's close callbacks = %d, want 1", count)
	}
}
