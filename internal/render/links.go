package render

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"vpnctl/internal/state"
)

// Links are parsed by Hiddify's ray2sing: it understands the "443,30000-39999"
// port list and normalises "obfs-password" to "obfspassword".

func HyLink(s *state.State, c *state.Client) string {
	ports := strconv.Itoa(s.HyPort)
	if s.HopRange != "" {
		ports += "," + s.HopRange
	}
	q := url.Values{}
	q.Set("obfs", "salamander")
	q.Set("obfs-password", s.HyObfs)
	q.Set("sni", s.SNI)
	q.Set("insecure", "1") // self-signed; salamander already authenticates the server
	return fmt.Sprintf("hysteria2://%s:%s@%s:%s/?%s#%s", c.Name, c.HyPass, s.Host, ports,
		q.Encode(), url.PathEscape(s.Name+" hy2"))
}

func vless(s *state.State, c *state.Client, port int, label string, transport url.Values) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", s.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", s.RealityPub)
	q.Set("sid", c.ShortID)
	for k, v := range transport {
		q[k] = v
	}
	return fmt.Sprintf("vless://%s@%s?%s#%s", c.UUID, net.JoinHostPort(s.Host, strconv.Itoa(port)),
		q.Encode(), url.PathEscape(s.Name+" "+label))
}

func XHTTPLink(s *state.State, c *state.Client) string {
	return vless(s, c, s.XrayPort, "xhttp", url.Values{"type": {"xhttp"}, "path": {s.XHTTPPath}, "mode": {"auto"}})
}

func GRPCLink(s *state.State, c *state.Client) string {
	return vless(s, c, s.GRPCPort, "grpc", url.Values{"type": {"grpc"}, "serviceName": {s.GRPCService}, "mode": {"gun"}})
}

func Links(s *state.State, c *state.Client) []string {
	return []string{HyLink(s, c), GRPCLink(s, c), XHTTPLink(s, c)}
}

func SubURL(s *state.State, c *state.Client) string {
	return fmt.Sprintf("https://%s/%s#%s", net.JoinHostPort(s.Host, strconv.Itoa(s.SubPort)), c.SubToken,
		url.PathEscape(s.Name))
}
