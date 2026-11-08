package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"vpnctl/internal/render"
	"vpnctl/internal/sni"
	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

var hopCandidates = []string{"20000-29999", "30000-39999", "40000-49999"}

func composeRunning() bool {
	if _, err := os.Stat(state.ComposeFile()); err != nil {
		return false
	}
	out, err := sys.ComposeOut("ps", "-q")
	return err == nil && out != ""
}

func parseRange(r string) (lo, hi int, err error) {
	a, b, found := strings.Cut(r, "-")
	if !found {
		return 0, 0, fmt.Errorf("диапазон должен быть вида 20000-29999: %q", r)
	}
	if lo, err = strconv.Atoi(a); err != nil {
		return
	}
	if hi, err = strconv.Atoi(b); err != nil {
		return
	}
	if lo < 1024 || hi > 65535 || lo >= hi {
		err = fmt.Errorf("плохой диапазон %q", r)
	}
	return
}

func Install(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	host := fs.String("host", "", "внешний IPv4 сервера (по умолчанию определяется сам)")
	name := fs.String("name", "", "имя сервера в клиентах (по умолчанию hostname)")
	sniFlag := fs.String("sni", "", "домен для REALITY (по умолчанию ищется среди соседей по /24)")
	hop := fs.String("hop", "", "диапазон UDP-портов для port hopping или off")
	subPort := fs.Int("sub-port", 8443, "TCP-порт сервера подписок")
	_ = fs.Parse(args)

	if !sys.Have("systemctl") {
		ui.Die("нужен systemd")
	}
	sys.EnsureDocker()
	sys.EnsureNft()

	s, err := state.Load()
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		ui.Die("не читается состояние: %v", err)
	}
	var newTCP []int // ports nobody of ours listens on yet
	if fresh {
		s = state.New(*subPort)
		newTCP = []int{s.XrayPort, s.GRPCPort, s.SubPort}
	} else {
		newTCP = s.Upgrade()
	}
	if *host != "" {
		if ip := net.ParseIP(*host); ip == nil || ip.To4() == nil {
			ui.Die("--host должен быть IPv4: %q", *host)
		}
		s.Host = *host
	}
	if s.Host == "" {
		if s.Host, err = sys.DetectHost(); err != nil {
			ui.Die("%v", err)
		}
	}
	if *name != "" {
		s.Name = *name
	}
	if s.Name == "" {
		h, _ := os.Hostname()
		s.Name = strings.SplitN(h, ".", 2)[0]
	}

	busy := []string{}
	if fresh && !composeRunning() && !sys.PortFree("udp", s.HyPort) {
		busy = append(busy, fmt.Sprintf("%d/udp", s.HyPort))
	}
	for _, p := range newTCP {
		if !sys.PortFree("tcp", p) {
			busy = append(busy, fmt.Sprintf("%d/tcp", p))
		}
	}
	if len(busy) > 0 {
		ui.Die("заняты порты: %s. Посмотри, кто их держит: sudo ss -lntup\n"+
			"  если это тестовый контейнер, убери его: sudo docker rm -f hy2test", strings.Join(busy, ", "))
	}

	switch {
	case *hop == "off":
		s.HopRange = ""
	case *hop != "":
		lo, hi, err := parseRange(*hop)
		if err != nil {
			ui.Die("%v", err)
		}
		if b := sys.UDPListenersIn(lo, hi); len(b) > 0 {
			ui.Die("в диапазоне %s уже слушают UDP-порты %v", *hop, b)
		}
		s.HopRange = *hop
	case fresh:
		for _, r := range hopCandidates {
			lo, hi, _ := parseRange(r)
			if len(sys.UDPListenersIn(lo, hi)) == 0 {
				s.HopRange = r
				break
			}
		}
		if s.HopRange == "" {
			ui.Warn("все стандартные диапазоны для port hopping заняты, работаю без него (задай --hop)")
		}
	}

	if *sniFlag != "" {
		if !sni.Check(*sniFlag) {
			if !ui.Confirm(fmt.Sprintf("%s не отвечает по TLS 1.3 + h2 с этого сервера. Всё равно взять?", *sniFlag)) {
				os.Exit(1)
			}
		}
		s.SNI = *sniFlag
	}
	if s.SNI == "" {
		s.SNI = sni.Pick(s.Host)
	}

	step := func(what string, err error) {
		if err != nil {
			ui.Die("%s: %v", what, err)
		}
		ui.OK("%s", what)
	}
	step("состояние сохранено в "+state.Dir, s.Save())
	changed, err := render.WriteServerFiles(s)
	step("конфиги hysteria и xray", err)
	step("BBR, fq и UDP-буферы (sysctl)", sys.ApplySysctl())
	step("бинарник в "+state.BinPath, sys.CopySelf())
	step("правила nftables и сервер подписок (systemd)", sys.InstallUnits())
	sys.OpenPorts(s)
	step("состояние сохранено", s.Save())
	ui.Info("скачиваю образы и запускаю контейнеры")
	step("контейнеры запущены", sys.Compose("up", "-d", "--pull", "missing", "--remove-orphans"))
	if len(changed) > 0 {
		// configs are bind-mounted: up does not recreate a container for a new config
		step("перезапущены с новыми конфигами: "+strings.Join(changed, ", "), sys.Compose(append([]string{"restart"}, changed...)...))
	}

	ui.Header("Готово")
	ui.KV("сервер", fmt.Sprintf("%s (%s)", s.Name, s.Host))
	ui.KV("hysteria2", fmt.Sprintf("%d/udp, port hopping: %s", s.HyPort, orDash(s.HopRange)))
	ui.KV("vless xhttp", fmt.Sprintf("%d/tcp, SNI %s", s.XrayPort, s.SNI))
	ui.KV("vless grpc", fmt.Sprintf("%d/tcp, SNI %s", s.GRPCPort, s.SNI))
	ui.KV("подписки", fmt.Sprintf("https://%s:%d/...", s.Host, s.SubPort))
	if len(s.Clients) == 0 {
		ui.Info("\nДобавь клиента: vpnctl add <имя>, например vpnctl add phone")
	}
	ui.Info("Сертификат подписок от Let's Encrypt появится в течение минуты, проверь: vpnctl status")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
