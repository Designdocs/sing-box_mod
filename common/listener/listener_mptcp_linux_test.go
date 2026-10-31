package listener

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/sys/unix"
)

func listenerProtocol(t *testing.T, listener net.Listener) int {
	t.Helper()
	raw, err := listener.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var protocol int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		protocol, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return protocol
}

func TestListenTCPMPTCPOptions(t *testing.T) {
	for _, fastOpen := range []bool{false, true} {
		for _, multipath := range []bool{false, true} {
			name := "tcp"
			if fastOpen {
				name += "/fastopen"
			}
			if multipath {
				name += "/multipath"
			} else {
				name += "/default"
			}
			t.Run(name, func(t *testing.T) {
				t.Setenv("GODEBUG", "multipathtcp=2")
				instance := New(Options{Context: context.Background(), Logger: log.StdLogger(), Listen: option.ListenOptions{TCPFastOpen: fastOpen, TCPMultiPath: multipath}})
				listener, err := instance.ListenTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				protocol := listenerProtocol(t, listener)
				if multipath && protocol != unix.IPPROTO_MPTCP {
					t.Skip("kernel does not support MPTCP; Go fell back to TCP")
				}
				if !multipath && protocol != unix.IPPROTO_TCP {
					t.Fatalf("default listener protocol = %d; want TCP", protocol)
				}
			})
		}
	}
}
