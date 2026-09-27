package naive

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
)

func TestUpdateUsersPreservesHTTP2Tunnel(t *testing.T) {
	in, _ := newTestInbound(t)
	proxy := startH2Proxy(t, in)
	target := startTarget(t)
	transport := newH2Transport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	upload, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+proxy.Listener.Addr().String(), upload)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target.Listener.Addr().String()
	req.Header.Set("Proxy-Authorization", basicAuth("user", "secret"))
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", response.StatusCode)
	}

	for _, users := range [][]auth.User{nil, {{Username: "new-user", Password: "new-secret"}}, testUsers} {
		in.UpdateUsers(users)
		// Every update must leave this already authenticated tunnel alive.
		if _, err := io.WriteString(writer, "GET /preserved HTTP/1.1\r\nHost: target\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		inner, err := http.ReadResponse(bufio.NewReader(response.Body), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(inner.Body)
		inner.Body.Close()
		if err != nil || string(body) != `path=/preserved auth=""` {
			t.Fatalf("body=%q err=%v", body, err)
		}
	}
}

func TestUpdateUsersConcurrentAuthentication(t *testing.T) {
	in, _ := newTestInbound(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			in.UpdateUsers(nil)
			in.UpdateUsers(testUsers)
		}
	}()
	for range 100 {
		request, _ := http.NewRequest(http.MethodGet, "http://"+probeHostFor("user", "secret"), nil)
		in.isProbeHost(request)
		request.Header.Set("Proxy-Authorization", basicAuth("user", "secret"))
		in.ServeHTTP(httptest.NewRecorder(), request)
	}
	wg.Wait()
}

func TestUpdateUsersKeepsPendingUserActive(t *testing.T) {
	in, _ := newTestInbound(t)
	release, ok := in.authenticate("user", "secret")
	if !ok {
		t.Fatal("initial authentication failed")
	}
	in.UpdateUsers(nil)
	if !in.UserActive("user") {
		t.Fatal("pending route lost its accounting reservation")
	}
	if _, ok := in.authenticate("user", "secret"); ok {
		t.Fatal("removed user authenticated")
	}
	release()
	release()
	if in.UserActive("user") {
		t.Fatal("finished request still retains user")
	}
}

func TestUpdateUsersPreservesHTTP1Tunnel(t *testing.T) {
	in, _ := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	target := startTarget(t)
	conn, reader := dialProxy(t, proxy)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", target.Listener.Addr(), target.Listener.Addr(), basicAuth("user", "secret"))
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", response.StatusCode)
	}
	in.UpdateUsers(nil)
	if !in.UserActive("user") {
		t.Fatal("HTTP/1 tunnel lost its accounting reservation")
	}
	fmt.Fprintf(conn, "GET /preserved HTTP/1.1\r\nHost: target\r\n\r\n")
	response, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != `path=/preserved auth=""` {
		t.Fatalf("body=%q err=%v", body, err)
	}
	conn.Close()
	for deadline := time.Now().Add(time.Second); in.UserActive("user"); {
		if time.Now().After(deadline) {
			t.Fatal("HTTP/1 tunnel accounting reservation did not drain")
		}
		time.Sleep(time.Millisecond)
	}
}
