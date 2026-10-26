// Adapted from github.com/anytls/sing-anytls v0.0.11 service.go.
// Copyright (C) 2025 anytls <github.com/anytls>
// SPDX-License-Identifier: GPL-3.0-or-later
// Keep the upstream session and pipe implementation; close failed streams and cancel sessions on inbound shutdown.

package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/common/compat/anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type service struct {
	users           atomic.TypedValue[map[[32]byte]string]
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

func newService(config anytls.ServiceConfig) (*service, error) {
	service := &service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.UpdateUsers(config.Users)

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func (s *service) UpdateUsers(users []anytls.User) {
	u := make(map[[32]byte]string)
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	s.users.Store(u)
}

// NewConnection `conn` should be plaintext
func (s *service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, authenticated func(string, [32]byte) bool) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	if user, ok := s.users.Load()[passwordSha256]; ok {
		ctx = auth.ContextWithUser(ctx, user)
		if !authenticated(user, passwordSha256) {
			return E.New("user or inbound no longer active")
		}
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	var serverSession *session.Session
	serverSession = session.NewServerSession(conn, func(stream *session.Stream) {
		if ctx.Err() != nil || serverSession.IsClosed() {
			_ = stream.Close()
			return
		}
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			N.CloseOnHandshakeFailure(stream, nil, err)
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	stop := context.AfterFunc(ctx, func() { _ = serverSession.Close() })
	defer stop()
	defer serverSession.Close()
	serverSession.Run()
	return nil
}

func (s *service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
