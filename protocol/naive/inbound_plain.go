package naive

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

// The challenge a plain proxy client receives on a missing or wrong
// Proxy-Authorization. Naive clients never see it (they get the connection
// dropped, as before), so nothing here identifies the server as naive.
const proxyAuthenticateChallenge = `Basic realm="proxy" charset="UTF-8"`

// isProxyRequest reports whether a non-CONNECT request names its target in
// absolute-URI form, the way a browser addresses an http:// origin through a
// proxy. Anything else is addressed to this server itself.
func isProxyRequest(request *http.Request) bool {
	return request.URL.Scheme != "" && request.URL.Host != ""
}

// forwardPlainHTTP serves a non-CONNECT request from a plain proxy client:
// the absolute-URI form a browser sends for http:// origins. The upstream
// connection is routed through the inbound's router like a tunnel would be,
// so routing rules, user attribution and traffic accounting all apply.
func (n *Inbound) forwardPlainHTTP(ctx context.Context, writer http.ResponseWriter, request *http.Request, userName string, source M.Socksaddr) {
	outbound := request.Clone(ctx)
	outbound.RequestURI = ""
	removeHopByHopHeaders(outbound.Header)

	var routeErr common.TypedValue[error]
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				input, output := pipe.Pipe()
				go n.routeConnection(ctx, output, userName, source, M.ParseSocksaddr(address).Unwrap(), func(it error) {
					routeErr.Store(it)
					common.Close(input, output)
				})
				return input, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	response, err := client.Do(outbound)
	if err != nil {
		http.Error(writer, "upstream request failed", http.StatusBadGateway)
		n.badRequest(ctx, request, E.Errors(routeErr.Load(), err))
		return
	}
	defer response.Body.Close()

	removeHopByHopHeaders(response.Header)
	header := writer.Header()
	for key, values := range response.Header {
		header[key] = values
	}
	writer.WriteHeader(response.StatusCode)
	_, err = io.Copy(writer, response.Body)
	if err != nil {
		n.badRequest(ctx, request, E.Cause(err, "copy upstream response"))
	}
}

// removeHopByHopHeaders strips the headers that describe this hop only
// (RFC 9110 §7.6.1) so neither side sees the proxy's own framing or credentials.
func removeHopByHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			header.Del(name)
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
		"Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}
