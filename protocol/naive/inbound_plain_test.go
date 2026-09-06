package naive

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

// directRouter dials the destination itself and records the user it saw, so
// the test can assert that plain clients are attributed like naive ones.
type directRouter struct {
	users chan string
}

func (r *directRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.users <- metadata.User
	upstream, err := net.Dial("tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	return bufio.CopyConn(ctx, conn, upstream)
}

func (r *directRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		err := r.RouteConnection(ctx, conn, metadata)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (r *directRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return E.New("udp not supported in test")
}

func (r *directRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func newTestInbound(t *testing.T) (*Inbound, *directRouter) {
	t.Helper()
	router := &directRouter{users: make(chan string, 8)}
	logger := log.NewNOPFactory().NewLogger("test")
	return &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeNaive, "test"),
		ctx:           context.Background(),
		router:        router,
		logger:        logger,
		listener:      listener.New(listener.Options{Context: context.Background(), Logger: logger, Listen: option.ListenOptions{}}),
		authenticator: auth.NewAuthenticator([]auth.User{{Username: "user", Password: "secret"}}),
	}, router
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// startTarget serves a page that echoes the request path and whether proxy
// credentials leaked through.
func startTarget(t *testing.T) *httptest.Server {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s auth=%q", r.URL.Path, r.Header.Get("Proxy-Authorization"))
	}))
	t.Cleanup(target.Close)
	return target
}

func dialProxy(t *testing.T, proxy *httptest.Server) (net.Conn, *std_bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, std_bufio.NewReader(conn)
}

func TestPlainConnectWithoutCredentialsIsChallenged(t *testing.T) {
	in, _ := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	conn, reader := dialProxy(t, proxy)
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", response.StatusCode)
	}
	if got := response.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("Proxy-Authenticate = %q, want a Basic challenge", got)
	}
}

func TestNaiveClientWithBadCredentialsIsStillDroppedSilently(t *testing.T) {
	in, _ := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	conn, reader := dialProxy(t, proxy)
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nPadding: ~~~~\r\n\r\n")
	if _, err := http.ReadResponse(reader, nil); err == nil {
		t.Fatal("naive client with bad credentials received a response; expected the connection to be dropped")
	}
}

func TestPlainConnectTunnelsWithoutPadding(t *testing.T) {
	in, router := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	target := startTarget(t)
	conn, reader := dialProxy(t, proxy)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		target.Listener.Addr(), target.Listener.Addr(), basicAuth("user", "secret"))
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if response.Header.Get("Padding") != "" {
		t.Fatal("plain client received a naive Padding header")
	}
	if user := <-router.users; user != "user" {
		t.Fatalf("routed user = %q, want user", user)
	}
	// Raw bytes through the tunnel: any padding frame would corrupt this request.
	fmt.Fprintf(conn, "GET /tunnel HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Listener.Addr())
	inner, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(inner.Body)
	if string(body) != `path=/tunnel auth=""` {
		t.Fatalf("tunnelled body = %q", body)
	}
}

func TestPlainAbsoluteURIRequestIsForwarded(t *testing.T) {
	in, router := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	target := startTarget(t)
	conn, reader := dialProxy(t, proxy)
	fmt.Fprintf(conn, "GET http://%s/plain HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		target.Listener.Addr(), target.Listener.Addr(), basicAuth("user", "secret"))
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != `path=/plain auth=""` {
		t.Fatalf("status = %d body = %q", response.StatusCode, body)
	}
	if user := <-router.users; user != "user" {
		t.Fatalf("routed user = %q, want user", user)
	}
}

func TestNaiveClientAbsoluteURIRequestIsStillRejected(t *testing.T) {
	in, _ := newTestInbound(t)
	proxy := httptest.NewServer(in)
	defer proxy.Close()
	conn, reader := dialProxy(t, proxy)
	fmt.Fprintf(conn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nPadding: ~~~~\r\nProxy-Authorization: %s\r\n\r\n", basicAuth("user", "secret"))
	if _, err := http.ReadResponse(reader, nil); err == nil {
		t.Fatal("naive client sending a non-CONNECT request received a response; expected a drop")
	}
}

// Browsers negotiate h2 with a TLS proxy and tunnel through a CONNECT stream.
func TestPlainConnectOverHTTP2TunnelsWithoutPadding(t *testing.T) {
	in, router := newTestInbound(t)
	proxy := httptest.NewUnstartedServer(in)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	target := startTarget(t)

	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	upload, uploadWriter := io.Pipe()
	defer uploadWriter.Close()
	request, err := http.NewRequest(http.MethodConnect, "https://"+proxy.Listener.Addr().String(), upload)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = target.Listener.Addr().String()
	request.Header.Set("Proxy-Authorization", basicAuth("user", "secret"))
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("proto = %s status = %d, want HTTP/2 200", response.Proto, response.StatusCode)
	}
	if response.Header.Get("Padding") != "" {
		t.Fatal("plain h2 client received a naive Padding header")
	}
	if user := <-router.users; user != "user" {
		t.Fatalf("routed user = %q, want user", user)
	}
	fmt.Fprintf(uploadWriter, "GET /h2 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Listener.Addr())
	inner, err := http.ReadResponse(std_bufio.NewReader(response.Body), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(inner.Body)
	if string(body) != `path=/h2 auth=""` {
		t.Fatalf("tunnelled body = %q", body)
	}
}
