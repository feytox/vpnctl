package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var hopCandidates = []string{"20000-29999", "30000-39999", "40000-49999"}

func composeRunning() bool {
	if _, err := os.Stat(composeFile()); err != nil {
		return false
	}
	out, err := composeOut("ps", "-q")
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

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	host := fs.String("host", "", "внешний IPv4 сервера (по умолчанию определяется сам)")
	name := fs.String("name", "", "имя сервера в клиентах (по умолчанию hostname)")
	sni := fs.String("sni", "", "домен для REALITY (по умолчанию ищется среди соседей по /24)")
	hop := fs.String("hop", "", "диапазон UDP-портов для port hopping или off")
	subPort := fs.Int("sub-port", 8443, "TCP-порт сервера подписок")
	_ = fs.Parse(args)

	if !have("systemctl") {
		die("нужен systemd")
	}
	ensureDocker()
	ensureNft()

	s, err := loadState()
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		die("не читается состояние: %v", err)
	}
	if fresh {
		s = &State{HyPort: 443, XrayPort: 443, SubPort: *subPort}
		s.HyObfs = randHex(16)
		s.RealityPriv, s.RealityPub = realityKeys()
		s.XHTTPPath = "/" + randHex(6)
	}
	if *host != "" {
		if ip := net.ParseIP(*host); ip == nil || ip.To4() == nil {
			die("--host должен быть IPv4: %q", *host)
		}
		s.Host = *host
	}
	if s.Host == "" {
		if s.Host, err = detectHost(); err != nil {
			die("%v", err)
		}
	}
	if *name != "" {
		s.Name = *name
	}
	if s.Name == "" {
		h, _ := os.Hostname()
		s.Name = strings.SplitN(h, ".", 2)[0]
	}

	if !composeRunning() {
		busy := []string{}
		if !portFree("udp", s.HyPort) {
			busy = append(busy, fmt.Sprintf("%d/udp", s.HyPort))
		}
		if !portFree("tcp", s.XrayPort) {
			busy = append(busy, fmt.Sprintf("%d/tcp", s.XrayPort))
		}
		if !portFree("tcp", s.SubPort) {
			busy = append(busy, fmt.Sprintf("%d/tcp", s.SubPort))
		}
		if len(busy) > 0 {
			die("заняты порты: %s. Посмотри, кто их держит: sudo ss -lntup | grep -E ':(443|%d) '\n"+
				"  если это тестовый контейнер, убери его: sudo docker rm -f hy2test", strings.Join(busy, ", "), s.SubPort)
		}
	}

	switch {
	case *hop == "off":
		s.HopRange = ""
	case *hop != "":
		lo, hi, err := parseRange(*hop)
		if err != nil {
			die("%v", err)
		}
		if b := udpListenersIn(lo, hi); len(b) > 0 {
			die("в диапазоне %s уже слушают UDP-порты %v", *hop, b)
		}
		s.HopRange = *hop
	case fresh:
		for _, r := range hopCandidates {
			lo, hi, _ := parseRange(r)
			if len(udpListenersIn(lo, hi)) == 0 {
				s.HopRange = r
				break
			}
		}
		if s.HopRange == "" {
			warn("все стандартные диапазоны для port hopping заняты, работаю без него (задай --hop)")
		}
	}

	if *sni != "" {
		if !checkSNI(*sni) {
			if !confirm(fmt.Sprintf("%s не отвечает по TLS 1.3 + h2 с этого сервера. Всё равно взять?", *sni)) {
				os.Exit(1)
			}
		}
		s.SNI = *sni
	}
	if s.SNI == "" {
		s.SNI = pickSNI(s.Host)
	}

	step := func(what string, err error) {
		if err != nil {
			die("%s: %v", what, err)
		}
		ok("%s", what)
	}
	step("состояние сохранено в "+stateDir, s.save())
	step("конфиги hysteria и xray", s.writeServerFiles())
	step("BBR, fq и UDP-буферы (sysctl)", applySysctl())
	step("бинарник в "+binPath, copySelf())
	step("правила nftables и сервер подписок (systemd)", installUnits())
	s.openPorts()
	step("состояние сохранено", s.save())
	info("скачиваю образы и запускаю контейнеры")
	step("контейнеры запущены", compose("up", "-d", "--pull", "missing", "--remove-orphans"))

	header("Готово")
	kv("сервер", fmt.Sprintf("%s (%s)", s.Name, s.Host))
	kv("hysteria2", fmt.Sprintf("%d/udp, port hopping: %s", s.HyPort, orDash(s.HopRange)))
	kv("vless xhttp", fmt.Sprintf("%d/tcp, SNI %s", s.XrayPort, s.SNI))
	kv("подписки", fmt.Sprintf("https://%s:%d/...", s.Host, s.SubPort))
	if len(s.Clients) == 0 {
		info("\nДобавь клиента: vpnctl add <имя>, например vpnctl add phone")
	}
	info("Сертификат подписок от Let's Encrypt появится в течение минуты, проверь: vpnctl status")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func applyClients(s *State) {
	if err := s.save(); err != nil {
		die("сохранение: %v", err)
	}
	if err := s.writeServerFiles(); err != nil {
		die("конфиги: %v", err)
	}
	if composeRunning() {
		if err := compose("restart", "hysteria", "xray"); err != nil {
			die("перезапуск контейнеров: %v", err)
		}
	} else {
		warn("контейнеры не запущены, изменения применятся при старте: vpnctl restart")
	}
}

func cmdAdd(args []string) {
	if len(args) != 1 {
		die("использование: vpnctl add <имя>")
	}
	name := args[0]
	if !clientNameRe.MatchString(name) {
		die("имя: латиница в нижнем регистре, цифры, - и _, до 32 символов")
	}
	s := mustState()
	if s.client(name) != nil {
		die("клиент %s уже есть. Ссылка: vpnctl show %s", name, name)
	}
	c := newClient(name)
	s.Clients = append(s.Clients, c)
	applyClients(s)
	ok("клиент %s добавлен", name)
	printClient(s, c, false)
}

func cmdDel(args []string) {
	if len(args) != 1 {
		die("использование: vpnctl del <имя>")
	}
	s := mustState()
	if s.client(args[0]) == nil {
		die("клиента %s нет", args[0])
	}
	if !confirm(fmt.Sprintf("Удалить клиента %s? Его подписка и ключи перестанут работать.", args[0])) {
		return
	}
	var keep []*Client
	for _, c := range s.Clients {
		if c.Name != args[0] {
			keep = append(keep, c)
		}
	}
	s.Clients = keep
	applyClients(s)
	ok("клиент %s удалён", args[0])
}

func cmdList() {
	s := mustState()
	if len(s.Clients) == 0 {
		info("клиентов нет. Добавь: vpnctl add <имя>")
		return
	}
	fmt.Printf("%-20s %s\n", "ИМЯ", "СОЗДАН")
	for _, c := range s.Clients {
		fmt.Printf("%-20s %s\n", c.Name, c.Created.Local().Format("2006-01-02 15:04"))
	}
}

func cmdShow(args []string) {
	if len(args) != 1 {
		die("использование: vpnctl show <имя>")
	}
	s := mustState()
	c := s.client(args[0])
	if c == nil {
		die("клиента %s нет", args[0])
	}
	printClient(s, c, true)
}

func printClient(s *State, c *Client, withLinks bool) {
	header("Подписка " + c.Name)
	info("%s", s.subURL(c))
	info("%sHiddify: + -> Добавить из буфера обмена. Обновляется сама раз в 12 ч.%s", cDim, cReset)
	if withLinks {
		header("Ссылки по отдельности")
		for _, l := range s.links(c) {
			info("%s", l)
		}
	}
}

func unitState(u string) string {
	out, _ := output("systemctl", "is-active", u)
	return out
}

func cmdStatus() {
	s := mustState()
	header(fmt.Sprintf("%s  %s", s.Name, s.Host))
	if out, err := composeOut("ps", "-a", "--format", "{{.Service}}\t{{.State}}\t{{.Status}}"); err == nil {
		seen := map[string]bool{}
		for _, line := range strings.Split(out, "\n") {
			f := strings.SplitN(line, "\t", 3)
			if len(f) == 3 {
				seen[f[0]] = true
				kv(f[0], colorState(f[1], f[1] == "running")+"  "+cDim+f[2]+cReset)
			}
		}
		for _, svc := range []string{"hysteria", "xray"} {
			if !seen[svc] {
				kv(svc, colorState("нет контейнера", false))
			}
		}
	} else {
		warn("docker compose ps: %v", err)
	}
	for _, u := range []string{subUnit, netUnit} {
		st := unitState(u)
		kv(strings.TrimSuffix(u, ".service"), colorState(st, st == "active"))
	}

	kv("hysteria2", fmt.Sprintf("%d/udp, port hopping: %s, obfs salamander", s.HyPort, orDash(s.HopRange)))
	kv("vless xhttp", fmt.Sprintf("%d/tcp, REALITY SNI %s", s.XrayPort, s.SNI))
	if _, err := output("nft", "list", "table", "inet", nftTable); err != nil && s.HopRange != "" {
		kv("nftables", colorState("таблицы нет, port hopping не работает", false))
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		cc := strings.TrimSpace(string(b))
		kv("TCP CC", colorState(cc, cc == "bbr"))
	}
	if c := readSubCert(); c == nil {
		kv("сертификат", colorState("нет", false))
	} else if isSelfSigned(c) {
		kv("сертификат", colorState("самоподписанный, Let's Encrypt ещё не выдал: vpnctl logs sub", false))
	} else {
		left := time.Until(c.NotAfter).Round(time.Hour)
		kv("сертификат", colorState(fmt.Sprintf("%s, до %s (%s)", c.Issuer.CommonName,
			c.NotAfter.Local().Format("2006-01-02 15:04"), left), left > 24*time.Hour))
	}
	kv("подписки", fmt.Sprintf("%d/tcp", s.SubPort))
	kv("клиенты", strconv.Itoa(len(s.Clients)))
}

func colorState(s string, good bool) string {
	if good {
		return cGreen + s + cReset
	}
	return cRed + s + cReset
}

func cmdLogs(args []string) {
	svc, follow := "", false
	for _, a := range args {
		if a == "-f" {
			follow = true
		} else {
			svc = a
		}
	}
	switch svc {
	case "sub":
		a := []string{"-u", subUnit, "-n", "100", "--no-pager"}
		if follow {
			a = append(a, "-f")
		}
		_ = run("journalctl", a...)
	case "", "hysteria", "xray":
		a := []string{"logs", "--tail", "100"}
		if follow {
			a = append(a, "-f")
		}
		if svc != "" {
			a = append(a, svc)
		}
		_ = compose(a...)
	default:
		die("использование: vpnctl logs [hysteria|xray|sub] [-f]")
	}
}

func cmdRestart() {
	mustState()
	if err := compose("up", "-d", "--force-recreate"); err != nil {
		die("контейнеры: %v", err)
	}
	if err := run("systemctl", "restart", netUnit, subUnit); err != nil {
		die("systemd: %v", err)
	}
	ok("перезапущено")
}

func cmdPurge() {
	s, err := loadState()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		die("не читается состояние: %v", err)
	}
	if !confirm("Удалить контейнеры и образы vpnctl, правила nftables, systemd-юниты, sysctl, все ключи и клиентов? Docker останется.") {
		return
	}
	if _, err := os.Stat(composeFile()); err == nil {
		if err := compose("down", "--rmi", "all", "--remove-orphans"); err != nil {
			warn("docker compose down: %v", err)
		}
	}
	_ = run("systemctl", "disable", "--now", "-q", subUnit, netUnit)
	_ = netDown()
	for _, f := range []string{unitDir + "/" + subUnit, unitDir + "/" + netUnit, sysctlFile, modulesFile} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			warn("%s: %v", f, err)
		}
	}
	_ = run("systemctl", "daemon-reload")
	if s != nil && ufwActive() {
		for _, r := range s.UFWRules {
			if err := run("ufw", "delete", "allow", r); err != nil {
				warn("ufw delete allow %s: %v", r, err)
			}
		}
	}
	if err := os.RemoveAll(stateDir); err != nil {
		warn("%s: %v", stateDir, err)
	}
	if err := os.Remove(binPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		warn("%s: %v", binPath, err)
	}
	ok("всё удалено. Значения sysctl (BBR, буферы) держатся до перезагрузки.")
}
