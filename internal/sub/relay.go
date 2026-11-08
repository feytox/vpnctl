package sub

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vpnctl/internal/state"
)

var remoteClient = &http.Client{Timeout: 15 * time.Second}

// relayHandler serves /<relay>/<token>: the remote server's subscription with
// entries through this server added. The remote knows nothing about us.
func relayHandler(w http.ResponseWriter, r *http.Request, s *state.State, rl *state.Relay, tok string) {
	u := fmt.Sprintf("https://%s/%s", net.JoinHostPort(rl.Host, strconv.Itoa(rl.SubPort)), url.PathEscape(tok))
	resp, err := remoteClient.Get(u)
	if err != nil {
		log.Printf("relay %s: %v", rl.Name, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, http.StatusText(resp.StatusCode), resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		raw = body
	}
	var via, direct []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		direct = append(direct, l)
		if v := relayLink(l, s, rl); v != "" {
			via = append(via, v)
		}
	}
	log.Printf("relay %s: subscription fetched from %s, %d entries via us", rl.Name, r.RemoteAddr, len(via))
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	title := resp.Header.Get("profile-title")
	if title == "" {
		title = rl.Name
	}
	h.Set("profile-title", title+" via "+s.Name)
	if v := resp.Header.Get("profile-update-interval"); v != "" {
		h.Set("profile-update-interval", v)
	}
	// via first: this URL is for networks where the direct entries do not work
	all := append(via, direct...)
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(all, "\n")))))
}

// relayLink returns the link pointed at our forwarded ports, "" if we do not
// forward the port it uses (e.g. XHTTP, or the remote changed its ports).
func relayLink(link string, s *state.State, rl *state.Relay) string {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return ""
	}
	end := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		end = i
	}
	auth, tail := rest[:end], rest[end:]
	at := strings.LastIndex(auth, "@") + 1
	colon := strings.LastIndex(auth, ":")
	if colon < at {
		return ""
	}
	host, ports := auth[at:colon], auth[colon+1:]
	if host != rl.Host {
		return ""
	}
	first, _, _ := strings.Cut(ports, ",")
	first, _, _ = strings.Cut(first, "-")
	var newPorts string
	switch {
	case scheme == "hysteria2" && first == strconv.Itoa(rl.HyPort):
		newPorts = rl.LocalHop
	case scheme == "vless" && ports == strconv.Itoa(rl.GRPCPort):
		newPorts = strconv.Itoa(rl.LocalGRPC)
	default:
		return ""
	}
	name := ""
	if i := strings.Index(tail, "#"); i >= 0 {
		name, _ = url.PathUnescape(tail[i+1:])
		tail = tail[:i]
	}
	return fmt.Sprintf("%s://%s%s:%s%s#%s", scheme, auth[:at], s.Host, newPorts, tail,
		url.PathEscape(strings.TrimSpace(name+" via "+s.Name)))
}
