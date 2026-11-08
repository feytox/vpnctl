package cli

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

const relayUsage = "использование: vpnctl relay [add ИМЯ IP [--hy 443] [--grpc 2053] [--sub 8443] | del ИМЯ]"

func Relay(args []string) {
	if len(args) == 0 {
		relayList(state.Must())
		return
	}
	switch args[0] {
	case "add":
		relayAdd(args[1:])
	case "del", "rm":
		relayDel(args[1:])
	case "list", "ls":
		relayList(state.Must())
	default:
		ui.Die(relayUsage)
	}
}

func relayAdd(args []string) {
	if len(args) < 2 {
		ui.Die(relayUsage)
	}
	name, host := args[0], args[1]
	fs := flag.NewFlagSet("relay add", flag.ExitOnError)
	hy := fs.Int("hy", 443, "UDP-порт hysteria2 на удалённом сервере")
	grpc := fs.Int("grpc", state.DefaultGRPCPort, "TCP-порт VLESS gRPC на удалённом сервере")
	subPort := fs.Int("sub", 8443, "TCP-порт подписок на удалённом сервере")
	_ = fs.Parse(args[2:])

	if !state.ClientNameRe.MatchString(name) {
		ui.Die("имя: латиница в нижнем регистре, цифры, - и _, до 32 символов")
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		ui.Die("IP должен быть IPv4: %q", host)
	}
	s := state.Must()
	if host == s.Host {
		ui.Die("%s - это адрес этого сервера", host)
	}
	for _, r := range s.Relays {
		if r.Name == name || r.Host == host {
			ui.Die("relay %s (%s) уже есть, сначала: vpnctl relay del %s", r.Name, r.Host, r.Name)
		}
	}
	r := &state.Relay{Name: name, Host: host, HyPort: *hy, GRPCPort: *grpc, SubPort: *subPort}
	if r.LocalHop = pickRelayHop(s); r.LocalHop == "" {
		ui.Die("нет свободного диапазона UDP-портов среди %v", relayHopCandidates)
	}
	if r.LocalGRPC = pickRelayTCP(s); r.LocalGRPC == 0 {
		ui.Die("нет свободного TCP-порта в 2054-2099")
	}

	cl := &http.Client{Timeout: 10 * time.Second}
	if resp, err := cl.Get(fmt.Sprintf("https://%s/", net.JoinHostPort(host, strconv.Itoa(r.SubPort)))); err != nil {
		ui.Warn("подписки %s:%d не отвечают или сертификат не от Let's Encrypt: %v", host, r.SubPort, err)
		if !ui.Confirm("Всё равно добавить?") {
			return
		}
	} else {
		resp.Body.Close()
	}

	s.Relays = append(s.Relays, r)
	applyRelays(s)
	ui.OK("relay %s добавлен", name)
	printRelay(s, r)
}

func relayDel(args []string) {
	if len(args) != 1 {
		ui.Die(relayUsage)
	}
	s := state.Must()
	if s.Relay(args[0]) == nil {
		ui.Die("relay %s нет", args[0])
	}
	if !ui.Confirm(fmt.Sprintf("Удалить relay %s? Записи через него у клиентов перестанут работать.", args[0])) {
		return
	}
	var keep []*state.Relay
	for _, r := range s.Relays {
		if r.Name != args[0] {
			keep = append(keep, r)
		}
	}
	s.Relays = keep
	applyRelays(s)
	ui.OK("relay %s удалён", args[0])
}

func applyRelays(s *state.State) {
	if err := s.Save(); err != nil {
		ui.Die("сохранение: %v", err)
	}
	// the subscription server re-reads the state on every request, only the rules need reloading
	if err := sys.Run("systemctl", "restart", state.NetUnit); err != nil {
		ui.Die("правила nftables: %v (подробности: journalctl -u %s)", err, state.NetUnit)
	}
}

func relayList(s *state.State) {
	if len(s.Relays) == 0 {
		ui.Info("relay нет. Добавить: vpnctl relay add <имя> <IP>")
		return
	}
	for _, r := range s.Relays {
		printRelay(s, r)
	}
}

func printRelay(s *state.State, r *state.Relay) {
	ui.Header(fmt.Sprintf("%s -> %s", r.Name, r.Host))
	ui.KV("hysteria2", fmt.Sprintf("%s/udp -> %d/udp", r.LocalHop, r.HyPort))
	ui.KV("vless grpc", fmt.Sprintf("%d/tcp -> %d/tcp", r.LocalGRPC, r.GRPCPort))
	ui.Info("Подписка через этот сервер: в ссылке клиента с %s (vpnctl show <клиент>) замени", r.Host)
	ui.Info("  https://%s/", net.JoinHostPort(r.Host, strconv.Itoa(r.SubPort)))
	ui.Info("на")
	ui.Info("  https://%s/%s/", net.JoinHostPort(s.Host, strconv.Itoa(s.SubPort)), r.Name)
}

var relayHopCandidates = append(append([]string{}, hopCandidates...), "50000-59999")

func overlaps(a, b string) bool {
	alo, ahi, err1 := parseRange(a)
	blo, bhi, err2 := parseRange(b)
	return err1 == nil && err2 == nil && alo <= bhi && blo <= ahi
}

func pickRelayHop(s *state.State) string {
next:
	for _, c := range relayHopCandidates {
		if overlaps(c, s.HopRange) {
			continue
		}
		for _, r := range s.Relays {
			if overlaps(c, r.LocalHop) {
				continue next
			}
		}
		lo, hi, _ := parseRange(c)
		if len(sys.UDPListenersIn(lo, hi)) == 0 {
			return c
		}
	}
	return ""
}

func pickRelayTCP(s *state.State) int {
	used := map[int]bool{80: true, s.XrayPort: true, s.GRPCPort: true, s.SubPort: true}
	for _, r := range s.Relays {
		used[r.LocalGRPC] = true
	}
	for p := state.DefaultGRPCPort + 1; p < 2100; p++ {
		if !used[p] && sys.PortFree("tcp", p) {
			return p
		}
	}
	return 0
}
