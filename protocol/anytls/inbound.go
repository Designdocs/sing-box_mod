package anytls

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	tlsConfig tls.ServerConfig
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *service
	connMu    sync.Mutex
	closed    bool
	userconns map[net.Conn]*inboundConnection
	uuidlist  []string
}

type inboundConnection struct {
	conn   net.Conn
	cancel context.CancelFunc
	user   string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	service, err := newService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return (anytls.User)(it)
		}),
		PaddingScheme: paddingScheme,
		Handler:       (*inboundHandler)(inbound),
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	uuidlist := make([]string, 0, len(options.Users))
	for _, user := range options.Users {
		uuidlist = append(uuidlist, user.Name)
	}
	inbound.userconns = make(map[net.Conn]*inboundConnection)
	inbound.uuidlist = uuidlist
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	h.connMu.Lock()
	h.closed = true
	connections := make([]*inboundConnection, 0, len(h.userconns))
	for _, connection := range h.userconns {
		connections = append(connections, connection)
	}
	clear(h.userconns)
	h.connMu.Unlock()
	for _, connection := range connections {
		connection.cancel()
		_ = connection.conn.Close()
	}
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx, cancel := context.WithCancel(ctx)
	connection := &inboundConnection{conn: conn, cancel: cancel, user: metadata.User}
	h.connMu.Lock()
	if h.closed {
		h.connMu.Unlock()
		cancel()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	h.userconns[connection.conn] = connection
	h.connMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = connection.conn.Close() })
	var err error
	defer func() {
		stop()
		cancel()
		_ = connection.conn.Close()
		h.connMu.Lock()
		delete(h.userconns, connection.conn)
		h.connMu.Unlock()
		if onClose != nil {
			onClose(err)
		}
	}()
	if h.tlsConfig != nil {
		var tlsConn net.Conn
		tlsConn, err = tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, nil, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err = h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, nil, func(user string, password [32]byte) bool {
		return h.authenticate(connection, user, password)
	})
	if err != nil {
		N.CloseOnHandshakeFailure(conn, nil, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) authenticate(connection *inboundConnection, user string, password [32]byte) bool {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	current, active := h.service.users.Load()[password]
	if h.closed || h.userconns[connection.conn] != connection || !active || current != user {
		return false
	}
	connection.user = user
	return true
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = h.listener.ListenOptions().InboundOptions
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
