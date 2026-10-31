package tcplistener

import (
	"context"
	"net"
)

// Listen disables MPTCP for auxiliary listeners, including embedded library use.
func Listen(network, address string) (net.Listener, error) {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	return config.Listen(context.Background(), network, address)
}
