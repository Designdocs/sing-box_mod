package vless

import (
	"crypto/tls"
	"github.com/sagernet/sing-box/log"
	"net"
	"testing"
)

// Exercise this under -race/checkptr. A stored uintptr loses allocation
// provenance before the TLS field offsets are added.
func TestVisionTLSBufferPointers(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := tls.Client(a, &tls.Config{})
	vision, err := NewVisionConn(conn, conn, [16]byte{}, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	if vision.input.Len() != 0 || vision.rawInput.Len() != 0 {
		t.Fatal("unexpected TLS buffer contents")
	}
}
