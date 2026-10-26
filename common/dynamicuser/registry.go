// Package dynamicuser coordinates immutable authentication snapshots with user
// revocation. A credential identity is never reused for a different account.
package dynamicuser

import (
	"context"
	"io"
	"net"
	"sync"

	N "github.com/sagernet/sing/common/network"
)

type User struct {
	Name   string
	Secret string
}

// String prevents credentials appearing in generic service error messages.
func (u User) String() string { return u.Name }

type entry struct {
	user   User
	conn   io.Closer
	cancel context.CancelFunc
}
type Registry struct {
	mu      sync.Mutex
	active  map[User]struct{}
	entries map[*entry]struct{}
	closed  bool
}

// Update publishes authentication and the admission gate under the same lock.
// Connections authenticated against an older snapshot must pass Track before
// routing, so removal cannot race with a late handshake.
func (r *Registry) Update(users []User, publish func() error) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if err := publish(); err != nil {
		r.mu.Unlock()
		return err
	}
	active := make(map[User]struct{}, len(users))
	for _, user := range users {
		active[user] = struct{}{}
	}
	r.active = active
	var revoked []*entry
	for e := range r.entries {
		if _, ok := active[e.user]; !ok {
			delete(r.entries, e)
			revoked = append(revoked, e)
		}
	}
	r.mu.Unlock()
	for _, e := range revoked {
		e.cancel()
		e.conn.Close()
	}
	return nil
}

func (r *Registry) Track(ctx context.Context, conn io.Closer, user User, onClose N.CloseHandlerFunc) (context.Context, N.CloseHandlerFunc, bool) {
	r.mu.Lock()
	_, ok := r.active[user]
	if !ok || r.closed {
		r.mu.Unlock()
		return ctx, onClose, false
	}
	child, cancel := context.WithCancel(ctx)
	e := &entry{user, conn, cancel}
	if r.entries == nil {
		r.entries = make(map[*entry]struct{})
	}
	r.entries[e] = struct{}{}
	r.mu.Unlock()
	stop := context.AfterFunc(child, func() { conn.Close() })
	done := N.OnceClose(func(err error) {
		stop()
		cancel()
		r.mu.Lock()
		delete(r.entries, e)
		r.mu.Unlock()
		if onClose != nil {
			onClose(err)
		}
	})
	return child, done, true
}

func (r *Registry) Close() error {
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = nil
	r.active = nil
	r.mu.Unlock()
	for e := range entries {
		e.cancel()
		e.conn.Close()
	}
	return nil
}

// Bind closes a pending handshake when its node is removed. The returned
// callback releases the cancellation registration after normal routing closes.
func Bind(ctx context.Context, conn io.Closer, onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return N.OnceClose(func(err error) {
		stop()
		if onClose != nil {
			onClose(err)
		}
	})
}
