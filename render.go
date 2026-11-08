package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func hyDir() string       { return filepath.Join(stateDir, "hysteria") }
func xrayDir() string     { return filepath.Join(stateDir, "xray") }
func subDir() string      { return filepath.Join(stateDir, "sub") }
func composeFile() string { return filepath.Join(stateDir, "compose.yaml") }

func (s *State) hysteriaConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "listen: :%d\n", s.HyPort)
	b.WriteString("tls:\n  cert: /etc/hysteria/cert.pem\n  key: /etc/hysteria/key.pem\n")
	fmt.Fprintf(&b, "obfs:\n  type: salamander\n  salamander:\n    password: %q\n", s.HyObfs)
	b.WriteString("auth:\n  type: userpass\n  userpass:\n")
	if len(s.Clients) == 0 {
		// hysteria refuses an empty userpass map; nobody knows this password
		fmt.Fprintf(&b, "    %q: %q\n", "none", randHex(16))
	}
	for _, c := range s.Clients {
		fmt.Fprintf(&b, "    %q: %q\n", c.Name, c.HyPass)
	}
	return b.String()
}

func (s *State) xrayConfig() ([]byte, error) {
	clients := []map[string]any{}
	shortIDs := []string{}
	for _, c := range s.Clients {
		clients = append(clients, map[string]any{"id": c.UUID, "email": c.Name, "flow": ""})
		shortIDs = append(shortIDs, c.ShortID)
	}
	if len(shortIDs) == 0 {
		shortIDs = append(shortIDs, randHex(8))
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "0.0.0.0",
			"port":     s.XrayPort,
			"protocol": "vless",
			"tag":      "xhttp-in",
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			"streamSettings": map[string]any{
				"network":       "xhttp",
				"xhttpSettings": map[string]any{"path": s.XHTTPPath},
				"security":      "reality",
				"realitySettings": map[string]any{
					"target":      net.JoinHostPort(s.SNI, "443"),
					"serverNames": []string{s.SNI},
					"privateKey":  s.RealityPriv,
					"shortIds":    shortIDs,
				},
			},
		}},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func (s *State) composeYAML() string {
	return fmt.Sprintf(`name: vpnctl
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
`, hysteriaImage, hyDir(), xrayImage, xrayDir())
}

// writeServerFiles renders hysteria/xray configs and compose.yaml from state.
// The hysteria certificate is created once and kept.
func (s *State) writeServerFiles() error {
	for _, d := range []string{hyDir(), xrayDir(), subDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	certPath := filepath.Join(hyDir(), "cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		cert, key, err := selfSigned(s.SNI, nil, 10*365*24*time.Hour)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(hyDir(), "key.pem"), key, 0o600); err != nil {
			return err
		}
		if err := writeFileAtomic(certPath, cert, 0o644); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(filepath.Join(hyDir(), "config.yaml"), []byte(s.hysteriaConfig()), 0o600); err != nil {
		return err
	}

	xcfg, err := s.xrayConfig()
	if err != nil {
		return err
	}
	xpath := filepath.Join(xrayDir(), "config.json")
	if err := writeFileAtomic(xpath, xcfg, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(composeFile(), []byte(s.composeYAML()), 0o600)
}

func (s *State) hyLink(c *Client) string {
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

func (s *State) vlessLink(c *Client) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", s.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", s.RealityPub)
	q.Set("sid", c.ShortID)
	q.Set("type", "xhttp")
	q.Set("path", s.XHTTPPath)
	q.Set("mode", "auto")
	return fmt.Sprintf("vless://%s@%s?%s#%s", c.UUID, net.JoinHostPort(s.Host, strconv.Itoa(s.XrayPort)),
		q.Encode(), url.PathEscape(s.Name+" xhttp"))
}

func (s *State) links(c *Client) []string {
	return []string{s.hyLink(c), s.vlessLink(c)}
}

func (s *State) subURL(c *Client) string {
	return fmt.Sprintf("https://%s/%s#%s", net.JoinHostPort(s.Host, strconv.Itoa(s.SubPort)), c.SubToken,
		url.PathEscape(s.Name))
}
