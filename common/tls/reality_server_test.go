//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestRealityServerPreservesX25519Identity(t *testing.T) {
	// RFC 7748's Alice key pair pins the existing base64 configuration format.
	privateKey, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	publicKey, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	server, err := NewRealityServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		ServerName: "example.com",
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
			ShortID:    []string{"0123456789abcdef"},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := server.(*RealityServerConfig)
	key, err := ecdh.X25519().NewPrivateKey(config.config.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Bytes(), privateKey) || !bytes.Equal(key.PublicKey().Bytes(), publicKey) {
		t.Fatal("REALITY key conversion changed the configured identity")
	}
	if config.config.Dest != "127.0.0.1:443" || !config.config.ServerNames["example.com"] || !config.config.ShortIds[[8]byte{1, 35, 69, 103, 137, 171, 205, 239}] {
		t.Fatal("REALITY handshake or authorization settings changed")
	}
}

func TestRealityServerRejectsInvalidPrivateKeys(t *testing.T) {
	for _, key := range []string{"!", "", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 33))} {
		_, err := NewRealityServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
			Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: key},
		})
		if err == nil {
			t.Fatal("accepted an invalid REALITY private key")
		}
	}
}
