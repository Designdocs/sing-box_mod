package route

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type endedNaivePacketConn struct{}

func (*endedNaivePacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}
func (*endedNaivePacketConn) WritePacket(packet *buf.Buffer, _ M.Socksaddr) error {
	packet.Release()
	return nil
}
func (*endedNaivePacketConn) Close() error { return nil }

func TestNaivePacketAccountingWaitsForBothCopies(t *testing.T) {
	for _, kind := range []string{C.TypeNaive, C.TypeHysteria2} {
		t.Run(kind, func(t *testing.T) {
			manager := NewConnectionManager(log.NewNOPFactory().NewLogger("test"))
			ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{InboundType: kind})
			source, destination := &endedNaivePacketConn{}, &endedNaivePacketConn{}
			var done atomic.Bool
			closed := 0
			onClose := func(error) { closed++ }
			manager.packetConnectionCopy(ctx, source, destination, false, &done, onClose)
			want := 1
			if kind == C.TypeNaive {
				want = 0
			}
			if closed != want {
				t.Fatalf("first direction: close callbacks=%d want=%d", closed, want)
			}
			manager.packetConnectionCopy(ctx, destination, source, true, &done, onClose)
			if closed != 1 {
				t.Fatalf("both directions: close callbacks=%d want=1", closed)
			}
		})
	}
}
