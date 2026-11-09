package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"vpnctl/internal/state"
	"vpnctl/internal/sub"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

func unitState(u string) string {
	out, _ := sys.Output("systemctl", "is-active", u)
	return out
}

func Status() {
	s := state.Must()
	ui.Header(fmt.Sprintf("%s  %s", s.Name, s.Host))
	if out, err := sys.ComposeOut("ps", "-a", "--format", "{{.Service}}\t{{.State}}\t{{.Status}}"); err == nil {
		seen := map[string]bool{}
		for _, line := range strings.Split(out, "\n") {
			f := strings.SplitN(line, "\t", 3)
			if len(f) == 3 {
				seen[f[0]] = true
				ui.KV(f[0], ui.Mark(f[1], f[1] == "running")+"  "+ui.Dim+f[2]+ui.Reset)
			}
		}
		for _, svc := range []string{"hysteria", "xray"} {
			if !seen[svc] {
				ui.KV(svc, ui.Mark("нет контейнера", false))
			}
		}
	} else {
		ui.Warn("docker compose ps: %v", err)
	}
	for _, u := range []string{state.SubUnit, state.NetUnit} {
		st := unitState(u)
		ui.KV(strings.TrimSuffix(u, ".service"), ui.Mark(st, st == "active"))
	}

	ui.KV("hysteria2", fmt.Sprintf("%d/udp, port hopping: %s, obfs salamander", s.HyPort, orDash(s.HopRange)))
	ui.KV("vless xhttp", fmt.Sprintf("%d/tcp, REALITY SNI %s", s.XrayPort, s.SNI))
	ui.KV("vless grpc", fmt.Sprintf("%d/tcp, REALITY SNI %s", s.GRPCPort, s.SNI))
	if _, err := sys.Output("nft", "list", "table", "inet", state.NftTable); err != nil && s.HopRange != "" {
		ui.KV("nftables", ui.Mark("таблицы нет, port hopping не работает", false))
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		cc := strings.TrimSpace(string(b))
		ui.KV("TCP CC", ui.Mark(cc, cc == "bbr"))
	}
	if c := sub.ReadCert(); c == nil {
		ui.KV("сертификат", ui.Mark("нет", false))
	} else if sub.IsSelfSigned(c) {
		ui.KV("сертификат", ui.Mark("самоподписанный, Let's Encrypt ещё не выдал: vpnctl logs sub", false))
	} else {
		left := time.Until(c.NotAfter).Round(time.Hour)
		ui.KV("сертификат", ui.Mark(fmt.Sprintf("%s, до %s (%s)", c.Issuer.CommonName,
			c.NotAfter.Local().Format("2006-01-02 15:04"), left), left > 24*time.Hour))
	}
	ui.KV("подписки", fmt.Sprintf("%d/tcp", s.SubPort))
	ui.KV("клиенты", strconv.Itoa(len(s.Clients)))
	for _, r := range s.Relays {
		ui.KV("relay "+r.Name, fmt.Sprintf("%s/udp, %d/tcp -> %s", r.LocalHop, r.LocalGRPC, r.Host))
	}
}
