// Package render turns the state into server configs, compose.yaml and
// client links.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpnctl/internal/gen"
	"vpnctl/internal/state"
)

func HysteriaConfig(s *state.State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "listen: :%d\n", s.HyPort)
	// sniGuard off: the certificate keeps the first SNI, and after `vpnctl sni` clients
	// send another one; under salamander the SNI is not visible anyway
	b.WriteString("tls:\n  cert: /etc/hysteria/cert.pem\n  key: /etc/hysteria/key.pem\n  sniGuard: disable\n")
	fmt.Fprintf(&b, "obfs:\n  type: salamander\n  salamander:\n    password: %q\n", s.HyObfs)
	b.WriteString("auth:\n  type: userpass\n  userpass:\n")
	if len(s.Clients) == 0 {
		// hysteria refuses an empty userpass map; nobody knows this password
		fmt.Fprintf(&b, "    %q: %q\n", "none", gen.RandHex(16))
	}
	for _, c := range s.Clients {
		fmt.Fprintf(&b, "    %q: %q\n", c.Name, c.HyPass)
	}
	return b.String()
}

func XrayConfig(s *state.State) ([]byte, error) {
	clients := []map[string]any{}
	shortIDs := []string{}
	for _, c := range s.Clients {
		clients = append(clients, map[string]any{"id": c.UUID, "email": c.Name, "flow": ""})
		shortIDs = append(shortIDs, c.ShortID)
	}
	if len(shortIDs) == 0 {
		shortIDs = append(shortIDs, gen.RandHex(8))
	}
	reality := map[string]any{
		"target":      net.JoinHostPort(s.SNI, "443"),
		"serverNames": []string{s.SNI},
		"privateKey":  s.RealityPriv,
		"shortIds":    shortIDs,
	}
	inbound := func(tag string, port int, network string, settings map[string]any) map[string]any {
		return map[string]any{
			"listen":   "0.0.0.0",
			"port":     port,
			"protocol": "vless",
			"tag":      tag,
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network":            network,
				network + "Settings": settings,
				"security":           "reality",
				"realitySettings":    reality,
			},
		}
	}
	inbounds := []any{
		inbound("xhttp-in", s.XrayPort, "xhttp", map[string]any{"path": s.XHTTPPath}),
		inbound("grpc-in", s.GRPCPort, "grpc", map[string]any{"serviceName": s.GRPCService}),
	}
	// the first outbound is the default one
	outbounds := []any{
		map[string]any{"protocol": "freedom", "tag": "direct"},
		map[string]any{"protocol": "blackhole", "tag": "block"},
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}}
	cfg["inbounds"], cfg["outbounds"] = inbounds, outbounds
	return json.MarshalIndent(cfg, "", "  ")
}

func Compose(s *state.State) string {
	c := fmt.Sprintf(`name: vpnctl
x-logging: &logging
  driver: json-file
  options: {max-size: 10m, max-file: "3"}
services:
  hysteria:
    image: %s
    network_mode: host
    restart: unless-stopped
    logging: *logging
    volumes: ["%s:/etc/hysteria:ro"]
    command: ["server", "-c", "/etc/hysteria/config.yaml"]
  xray:
    image: %s
    # the image user is 65532, which cannot bind 443 in the host network namespace
    user: "0:0"
    network_mode: host
    restart: unless-stopped
    logging: *logging
    volumes: ["%s:/etc/xray:ro"]
    command: ["run", "-c", "/etc/xray/config.json"]
`, state.HysteriaImage, state.HysteriaDir(), state.XrayImage, state.XrayDir())
	return c
}

// writeIfChanged reports whether the file content changed.
func writeIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	return true, state.WriteFile(path, data, perm)
}

// WriteServerFiles renders hysteria/xray configs and compose.yaml and returns
// the services whose config changed: configs are bind-mounted, so `compose up`
// alone does not reload them. The hysteria certificate is created once and kept.
func WriteServerFiles(s *state.State) (changed []string, err error) {
	for _, d := range []string{state.HysteriaDir(), state.XrayDir(), state.SubDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	certPath := filepath.Join(state.HysteriaDir(), "cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		cert, key, err := gen.SelfSigned(s.SNI, nil, 10*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		if err := state.WriteFile(filepath.Join(state.HysteriaDir(), "key.pem"), key, 0o600); err != nil {
			return nil, err
		}
		if err := state.WriteFile(certPath, cert, 0o644); err != nil {
			return nil, err
		}
	}
	hy, err := writeIfChanged(filepath.Join(state.HysteriaDir(), "config.yaml"), []byte(HysteriaConfig(s)), 0o600)
	if err != nil {
		return nil, err
	}
	if hy {
		changed = append(changed, "hysteria")
	}
	xcfg, err := XrayConfig(s)
	if err != nil {
		return nil, err
	}
	xr, err := writeIfChanged(filepath.Join(state.XrayDir(), "config.json"), xcfg, 0o600)
	if err != nil {
		return nil, err
	}
	if xr {
		changed = append(changed, "xray")
	}
	return changed, state.WriteFile(state.ComposeFile(), []byte(Compose(s)), 0o600)
}
