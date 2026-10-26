package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dynamicuser"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

var (
	ConfigureHTTP3ListenerFunc func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error)
	WrapError                  func(error) error
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	connections      dynamicuser.Registry
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	options          option.NaiveInboundOptions
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	probeHosts       map[string]string
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
		authenticator:    auth.NewAuthenticator(options.Users),
		probeHosts:       probeHostIndex(options.Users),
	}
	if common.Contains(inbound.network, N.NetworkUDP) {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("TLS is required for QUIC server")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	users := make([]dynamicuser.User, 0, len(options.Users))
	for _, user := range options.Users {
		users = append(users, dynamicuser.User{Name: user.Username})
	}
	_ = inbound.connections.Update(users, func() error { return nil })
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(n.connections.Close)
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(n.tlsConfig.Close)
	}
	scope.Add(n.listener.Close)
	if common.Contains(n.network, N.NetworkTCP) {
		tcpListener, err := n.listener.ListenTCP()
		if err != nil {
			return err
		}
		n.httpServer = &http.Server{
			//nolint:staticcheck
			Handler: h2c.NewHandler(n, &http2.Server{}),
			BaseContext: func(listener net.Listener) context.Context {
				return n.ctx
			},
		}
		listener := net.Listener(tcpListener)
		if n.tlsConfig != nil {
			if len(n.tlsConfig.NextProtos()) == 0 {
				n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
			} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
				n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
			}
			listener = aTLS.NewListener(tcpListener, n.tlsConfig)
		}
		go func() {
			sErr := n.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				n.logger.Error("http server serve error: ", sErr)
			}
		}()
		scope.Add(n.httpServer.Close)
	}

	if common.Contains(n.network, N.NetworkUDP) {
		http3Server, err := ConfigureHTTP3ListenerFunc(n.ctx, n.logger, n.listener, n, n.tlsConfig, n.options)
		if err == nil {
			scope.Add(http3Server.Close)
		} else if len(n.network) > 1 {
			n.logger.Warn(E.Cause(err, "naive http3 disabled"))
		} else {
			return err
		}
	}

	return nil
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	// A request without the naive Padding header comes from a plain HTTPS
	// proxy client (a browser, curl -x https://...), not from a naive client.
	// Such clients get a standard forward proxy on the same port and with the
	// same users: CONNECT tunnels carry no padding frames and absolute-URI
	// requests are forwarded as plain HTTP. Naive clients are served exactly
	// as before, including the silent connection drop on bad requests.
	plainClient := request.Header.Get("Padding") == ""
	if request.Method != "CONNECT" && !plainClient {
		rejectHTTP(writer, http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("not CONNECT request"))
		return
	}
	if plainClient && request.Method != "CONNECT" && !isProxyRequest(request) {
		// An origin-form request (GET / and the like) is addressed to this
		// host, not through it: a browser reachability probe or a scanner.
		// It is answered like any web server would, with no challenge, so a
		// bare visit neither fails with an unexpected 407 nor reveals a proxy.
		http.NotFound(writer, request)
		return
	}
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = n.authenticator.Verify(userName, password)
	}
	if !authOk {
		if !plainClient {
			rejectHTTP(writer, http.StatusProxyAuthRequired)
			n.badRequest(ctx, request, E.New("authorization failed"))
			return
		}
		n.rejectPlainClient(ctx, writer, request)
		return
	}
	source := sHttp.SourceAddress(request)
	if plainClient && n.isProbeHost(request) {
		// The credential-priming request: the browser now holds working
		// credentials for this proxy and there is nothing to reach.
		writer.Header().Set("Content-Length", "0")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != "CONNECT" {
		n.forwardPlainHTTP(ctx, writer, request, userName, source)
		return
	}
	if !plainClient {
		writer.Header().Set("Padding", generatePaddingHeader())
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()

	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	destination := M.ParseSocksaddr(hostPort).Unwrap()

	if hijacker, isHijacker := writer.(http.Hijacker); isHijacker {
		conn, reader, err := hijacker.Hijack()
		if err != nil {
			n.badRequest(ctx, request, E.New("hijack failed"))
			return
		}
		if cacheLen := reader.Reader.Buffered(); cacheLen > 0 {
			cache := buf.NewSize(cacheLen)
			if _, err := cache.ReadFullFrom(reader.Reader, cacheLen); err != nil {
				cache.Release()
				_ = conn.Close()
				n.badRequest(ctx, request, E.Cause(err, "read cache"))
				return
			}
			conn = bufio.NewCachedConn(conn, cache)
		}
		// net/http cancels the request context as soon as this handler
		// returns, hijacked or not, and the router copies under that context.
		// The tunnel outlives the handler, so it must not inherit the cancel.
		n.newConnection(context.WithoutCancel(ctx), false, newNaiveH1Conn(conn, !plainClient), userName, source, destination)
	} else {
		conn := newNaiveH2Conn(request.Body, writer, !plainClient)
		conn.remoteAddress = source
		n.newConnection(ctx, true, conn, userName, source, destination)
	}
}

func (n *Inbound) newConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if !waitForClose {
		n.routeConnection(ctx, conn, userName, source, destination, nil)
		return
	}
	done := make(chan struct{})
	wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
	n.routeConnection(ctx, conn, userName, source, destination, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	wrapper.CloseWrapper()
}

func (n *Inbound) routeConnection(ctx context.Context, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound connection from ", source)
		n.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	metadata.InboundOptions = n.listener.ListenOptions().InboundOptions
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	ctx, onClose, admitted := n.connections.Track(ctx, conn, dynamicuser.User{Name: userName}, onClose)
	if !admitted {
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	stop := context.AfterFunc(n.ctx, func() { conn.Close() })
	previous := onClose
	onClose = N.OnceClose(func(err error) { stop(); previous(err) })
	n.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (n *Inbound) isProbeHost(request *http.Request) bool {
	_, found := n.probeHosts[requestTargetHostname(request)]
	return found
}

// rejectPlainClient answers a plain client that presented no valid
// credentials. Only a request for the client's own probe host earns the 407
// that names the authentication scheme; anything else, CONNECT included, is
// a 404 with no challenge, so a prober holding no credentials sees a web
// server that has nothing at that address, never a proxy.
func (n *Inbound) rejectPlainClient(ctx context.Context, writer http.ResponseWriter, request *http.Request) {
	if !n.isProbeHost(request) {
		http.NotFound(writer, request)
		n.logger.DebugContext(ctx, "unauthenticated plain request from ", request.RemoteAddr, " answered 404")
		return
	}
	// Browsers only send credentials after a 407 that names the scheme.
	writer.Header().Set("Proxy-Authenticate", proxyAuthenticateChallenge)
	writer.Header().Set("Content-Length", "0")
	writer.WriteHeader(http.StatusProxyAuthRequired)
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func rejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)
		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
