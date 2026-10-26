package inbound

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type testOptions struct{ fail bool }
type managedTestInbound struct {
	Adapter
	ctx    context.Context
	stages []adapter.StartStage
	fail   bool
	closed int
}

func (i *managedTestInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	i.stages = append(i.stages, stage)
	if stage == adapter.StartStateStart {
		scope.Add(func() error { i.closed++; return nil })
		if i.fail {
			return errors.New("start failed")
		}
	}
	return nil
}
func TestDynamicScopeLifecycleAndFailedReplacement(t *testing.T) {
	registry := NewRegistry()
	var created []*managedTestInbound
	Register[testOptions](registry, "test", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts testOptions) (adapter.Inbound, error) {
		i := &managedTestInbound{Adapter: NewAdapter("test", tag), ctx: ctx, fail: opts.fail}
		created = append(created, i)
		return i, nil
	})
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	defer scope.Close()
	m := NewManager(registry, nil)
	for _, stage := range adapter.ListStartStages {
		if err := m.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	create := func(tag string, fail bool) error {
		return m.Create(context.Background(), nil, logger, tag, "test", &testOptions{fail})
	}
	if err := create("node", false); err != nil {
		t.Fatal(err)
	}
	original := created[0]
	if len(original.stages) != len(adapter.ListStartStages) {
		t.Fatal("dynamic node missed lifecycle stages")
	}
	if err := create("node", true); err == nil {
		t.Fatal("failed replacement accepted")
	}
	if current, _ := m.Get("node"); current != original {
		t.Fatal("failed replacement discarded original node")
	}
	if original.ctx.Err() != nil || created[1].ctx.Err() == nil || created[1].closed != 1 {
		t.Fatal("failed start cleanup changed original or leaked replacement")
	}
	if err := m.Remove("node"); err != nil {
		t.Fatal(err)
	}
	if original.ctx.Err() == nil || original.closed != 1 {
		t.Fatal("removal did not cancel and close node")
	}
	for range 100 {
		if err := create("churn", false); err != nil {
			t.Fatal(err)
		}
		if err := m.Remove("churn"); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.entries) != 0 || len(m.inbounds) != 0 {
		t.Fatal("removed nodes retained")
	}
	if err := create("last", false); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if created[len(created)-1].closed != 1 {
		t.Fatal("shutdown did not close active node once")
	}
	if err := create("closed", false); err == nil {
		t.Fatal("closed manager accepted node")
	}
}
