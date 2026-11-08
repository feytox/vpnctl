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
	return hyLink(s, c, ports, "hy2")
}

// HyWarpLink points at the second hysteria instance, which exits through WARP.
func HyWarpLink(s *state.State, c *state.Client) string {
	return hyLink(s, c, strconv.Itoa(s.Warp.HyPort), "warp hy2")
}

func hyLink(s *state.State, c *state.Client, ports, label string) string {
	q := url.Values{}
	q.Set("obfs", "salamander")
	q.Set("obfs-password", s.HyObfs)
	q.Set("sni", s.SNI)
	q.Set("insecure", "1") // self-signed; salamander already authenticates the server
	return fmt.Sprintf("hysteria2://%s:%s@%s:%s/?%s#%s", c.Name, c.HyPass, s.Host, ports,
		q.Encode(), url.PathEscape(s.Name+" "+label))
}

func vless(s *state.State, uuid, sid string, port int, label string, transport url.Values) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", s.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", s.RealityPub)
	q.Set("sid", sid)
	for k, v := range transport {
		q[k] = v
	}
	return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, net.JoinHostPort(s.Host, strconv.Itoa(port)),
		q.Encode(), url.PathEscape(s.Name+" "+label))
}

func XHTTPLink(s *state.State, c *state.Client) string {
	return vless(s, c.UUID, c.ShortID, s.XrayPort, "xhttp", url.Values{"type": {"xhttp"}, "path": {s.XHTTPPath}, "mode": {"auto"}})
}

func GRPCLink(s *state.State, c *state.Client) string {
	return grpcLink(s, c.UUID, c.ShortID, "grpc")
}

// GRPCWarpLink uses the client's WARP user: Xray routes it to WARP by email.
func GRPCWarpLink(s *state.State, c *state.Client) string {
	return grpcLink(s, c.WarpUUID, c.ShortID, "warp grpc")
}

func grpcLink(s *state.State, uuid, sid, label string) string {
	return vless(s, uuid, sid, s.GRPCPort, label, url.Values{"type": {"grpc"}, "serviceName": {s.GRPCService}, "mode": {"gun"}})
}

// Links go into the subscription. XHTTP is left out: Hiddify 5.5 XHTTP does not
// reach the pinned Xray 26.6.27 (REALITY via gRPC with the same keys works).
// Bring it back once Xray can be updated (see state.XrayHold) and it is retested.
// WARP entries go last, so they are never the default one.
func Links(s *state.State, c *state.Client) []string {
	links := []string{HyLink(s, c), GRPCLink(s, c)}
	if s.Warp != nil && c.WarpUUID != "" {
		links = append(links, HyWarpLink(s, c), GRPCWarpLink(s, c))
	}
	return links
}

func SubURL(s *state.State, c *state.Client) string {
	return fmt.Sprintf("https://%s/%s#%s", net.JoinHostPort(s.Host, strconv.Itoa(s.SubPort)), c.SubToken,
		url.PathEscape(s.Name))
}
