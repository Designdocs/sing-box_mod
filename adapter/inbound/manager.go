package inbound

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type managedInbound struct {
	scope  *adapter.Scope
	cancel context.CancelFunc
	bound  bool
}

func (e *managedInbound) bind(parent *adapter.Scope) {
	if e.bound {
		return
	}
	e.bound = true
	stop := context.AfterFunc(parent.Context(), e.cancel)
	e.scope.Add(func() error { stop(); return nil })
}

type Manager struct {
	registry adapter.InboundRegistry
	endpoint adapter.EndpointManager
	// Lifecycle callbacks may query the manager, so they run without access.
	operation    sync.Mutex
	access       sync.Mutex
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
	entries      map[adapter.Inbound]*managedInbound
	scope        *adapter.Scope
	stage        adapter.StartStage
	started      bool
	closed       bool
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{registry: registry, endpoint: endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
		entries:      make(map[adapter.Inbound]*managedInbound)}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	if m.closed {
		return os.ErrClosed
	}
	if m.scope == nil {
		m.scope = scope
		// Removed node scopes must not remain in the parent's cleanup list.
		scope.Add(m.Close)
	}
	m.started, m.stage = true, stage
	for _, inbound := range m.Inbounds() {
		entry := m.entries[inbound]
		entry.bind(scope)
		if err := entry.scope.Start(inboundName(inbound), inbound, stage); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Close() error {
	m.operation.Lock()
	defer m.operation.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.access.Lock()
	inbounds := m.inbounds
	m.inbounds = nil
	clear(m.inboundByTag)
	entries := m.entries
	m.entries = make(map[adapter.Inbound]*managedInbound)
	m.access.Unlock()
	var errs []error
	for _, inbound := range slices.Backward(inbounds) {
		if err := entries[inbound].scope.Close(); err != nil {
			errs = append(errs, E.Cause(err, "close ", inboundName(inbound)))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.inbounds)
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	if m.endpoint != nil {
		return m.endpoint.Get(tag)
	}
	return nil, false
}

func (m *Manager) Remove(tag string) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	entry := m.entries[inbound]
	delete(m.inboundByTag, tag)
	delete(m.entries, inbound)
	m.inbounds = slices.DeleteFunc(m.inbounds, func(it adapter.Inbound) bool { return it == inbound })
	m.access.Unlock()
	return entry.scope.Close()
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	if m.closed {
		return os.ErrClosed
	}
	if m.scope != nil && m.scope.Context().Err() != nil {
		return m.scope.Context().Err()
	}
	ctx, cancel := context.WithCancel(ctx)
	entry := &managedInbound{scope: adapter.NewScope(ctx, logger), cancel: cancel}
	entry.scope.Add(func() error { cancel(); return nil })
	if m.scope != nil {
		entry.bind(m.scope)
	}
	inbound, err := m.registry.Create(entry.scope.Context(), router, logger, tag, inboundType, options)
	if err != nil {
		_ = entry.scope.Close()
		return err
	}
	if m.started {
		for _, stage := range adapter.ListStartStages {
			if stage > m.stage {
				break
			}
			if err = entry.scope.Start(inboundName(inbound), inbound, stage); err != nil {
				return errors.Join(err, entry.scope.Close())
			}
		}
	}
	if entry.scope.Context().Err() != nil {
		return errors.Join(entry.scope.Context().Err(), entry.scope.Close())
	}
	m.access.Lock()
	previous, loaded := m.inboundByTag[tag]
	previousEntry := m.entries[previous]
	m.access.Unlock()
	if loaded {
		if err = previousEntry.scope.Close(); err != nil {
			return errors.Join(err, entry.scope.Close())
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	if loaded {
		delete(m.entries, previous)
		m.inbounds = slices.DeleteFunc(m.inbounds, func(it adapter.Inbound) bool { return it == previous })
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	m.entries[inbound] = entry
	return nil
}

func inboundName(inbound adapter.Inbound) string {
	return "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
}
