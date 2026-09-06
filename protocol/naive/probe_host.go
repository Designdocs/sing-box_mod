package naive

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing/common/auth"
)

// A plain client primes the browser's proxy credential cache by requesting
// one hostname that only it and this server can name: the hash of its own
// credentials under a reserved TLD (RFC 2606), so it can never be sent to
// the open internet by mistake. That request is the only one this server
// ever challenges with 407; every other unauthenticated request is answered
// 404 like a web server with nothing to say. An active prober that does
// not hold a user's credentials therefore never learns that a proxy is here,
// while a browser that does hold them gets its 407 on the first request and
// sends Proxy-Authorization pre-emptively on every CONNECT after it.
const probeHostSuffix = ".invalid"

const probeHostDigestLength = 16

// probeHostFor derives the credential-priming hostname for one user. The
// browser extension computes the same value, so the derivation is a contract.
func probeHostFor(username, password string) string {
	digest := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(digest[:])[:probeHostDigestLength] + probeHostSuffix
}

// probeHostIndex maps every user's probe host back to the user.
func probeHostIndex(users []auth.User) map[string]string {
	index := make(map[string]string, len(users))
	for _, user := range users {
		index[probeHostFor(user.Username, user.Password)] = user.Username
	}
	return index
}

// requestTargetHostname is the host a proxy request is addressed to, without
// the port: the CONNECT authority, the absolute-URI host, or on HTTP/2 the
// :authority pseudo-header.
func requestTargetHostname(request *http.Request) string {
	hostPort := request.URL.Host
	if hostPort == "" {
		hostPort = request.Host
	}
	return hostnameOf(hostPort)
}

func hostnameOf(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.Trim(hostPort, "[]"))
}
