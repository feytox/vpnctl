package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func output(name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && errb.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), err
}

func have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func compose(args ...string) error {
	return run("docker", append([]string{"compose", "-f", composeFile()}, args...)...)
}

func composeOut(args ...string) (string, error) {
	return output("docker", append([]string{"compose", "-f", composeFile()}, args...)...)
}

// ensureRoot re-runs the command through sudo when needed.
func ensureRoot() {
	if os.Geteuid() == 0 {
		return
	}
	self, err := os.Executable()
	if err != nil {
		die("нужен root: %v", err)
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		die("нужен root, а sudo не найден")
	}
	cmd := exec.Command(sudo, append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		die("%v", err)
	}
	os.Exit(0)
}

func aptInstall(pkgs ...string) error {
	if !have("apt-get") {
		return fmt.Errorf("нет apt-get, поставь вручную: %s", strings.Join(pkgs, " "))
	}
	cmd := exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		_ = run("apt-get", "update", "-q")
		cmd = exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	return nil
}

func ensureDocker() {
	if have("docker") {
		if _, err := output("docker", "compose", "version"); err != nil {
			info("ставлю docker compose plugin")
			if err := aptInstall("docker-compose-plugin"); err != nil {
				die("нет docker compose: %v", err)
			}
		}
		return
	}
	if !confirm("Docker не установлен. Поставить через get.docker.com?") {
		die("без docker не получится")
	}
	if !have("curl") {
		if err := aptInstall("curl"); err != nil {
			die("%v", err)
		}
	}
	if err := run("sh", "-c", "curl -fsSL https://get.docker.com | sh"); err != nil {
		die("установка docker не удалась: %v", err)
	}
	_ = run("systemctl", "enable", "--now", "docker")
}

func ensureNft() {
	if have("nft") {
		return
	}
	info("ставлю nftables")
	if err := aptInstall("nftables"); err != nil {
		die("%v", err)
	}
}

const sysctlConf = `# vpnctl: BBR for TCP from the server, bigger UDP buffers for QUIC
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
`

func applySysctl() error {
	if err := os.WriteFile(modulesFile, []byte("tcp_bbr\n"), 0o644); err != nil {
		return err
	}
	_ = run("modprobe", "tcp_bbr")
	if err := os.WriteFile(sysctlFile, []byte(sysctlConf), 0o644); err != nil {
		return err
	}
	_, err := output("sysctl", "-p", sysctlFile)
	return err
}

func (s *State) nftRules() string {
	var b strings.Builder
	// the empty definition makes delete safe when the table does not exist yet
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	b.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	if s.HopRange != "" {
		fmt.Fprintf(&b, "    udp dport %s redirect to :%d\n", s.HopRange, s.HyPort)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func nftFile() string { return filepath.Join(stateDir, "rules.nft") }

func netUp() error {
	s, err := loadState()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(nftFile(), []byte(s.nftRules()), 0o600); err != nil {
		return err
	}
	_, err = output("nft", "-f", nftFile())
	return err
}

func netDown() error {
	if _, err := output("nft", "list", "table", "inet", nftTable); err != nil {
		return nil
	}
	_, err := output("nft", "delete", "table", "inet", nftTable)
	return err
}

func netUnitText() string {
	return fmt.Sprintf(`[Unit]
Description=vpnctl nftables rules (port hopping)
After=network-pre.target nftables.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%[1]s net-up
ExecStop=%[1]s net-down

[Install]
WantedBy=multi-user.target
`, binPath)
}

func subUnitText() string {
	return fmt.Sprintf(`[Unit]
Description=vpnctl subscription server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, binPath)
}

func installUnits() error {
	for name, text := range map[string]string{netUnit: netUnitText(), subUnit: subUnitText()} {
		if err := os.WriteFile(filepath.Join(unitDir, name), []byte(text), 0o644); err != nil {
			return err
		}
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "-q", netUnit, subUnit); err != nil {
		return err
	}
	if err := run("systemctl", "restart", netUnit); err != nil {
		return err
	}
	return run("systemctl", "restart", subUnit)
}

// copySelf puts the running binary to binPath so systemd units can use it.
func copySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self == binPath {
		return nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return writeFileAtomic(binPath, data, 0o755)
}

func ufwActive() bool {
	if !have("ufw") {
		return false
	}
	out, err := output("ufw", "status")
	return err == nil && strings.HasPrefix(out, "Status: active")
}

// openPorts adds ufw rules when ufw is active. Port hopping needs no rules:
// the redirect happens in prerouting, before the input filter sees the packet.
func (s *State) openPorts() {
	if !ufwActive() {
		return
	}
	want := []string{
		fmt.Sprintf("%d/udp", s.HyPort),
		fmt.Sprintf("%d/tcp", s.XrayPort),
		fmt.Sprintf("%d/tcp", s.SubPort),
		"80/tcp", // ACME http-01 for the subscription certificate
	}
	status, _ := output("ufw", "status")
	for _, r := range want {
		if contains(s.UFWRules, r) || ufwHas(status, r) {
			continue // a rule the user had before stays theirs, purge will not touch it
		}
		if err := run("ufw", "allow", r); err != nil {
			warn("ufw allow %s: %v", r, err)
			continue
		}
		s.UFWRules = append(s.UFWRules, r)
	}
}

// ufwHas reports whether `ufw status` already allows rule ("443/udp"); a bare "443" covers both protocols.
func ufwHas(status, rule string) bool {
	port, _, _ := strings.Cut(rule, "/")
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "ALLOW" && (f[0] == rule || f[0] == port) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func portFree(network string, port int) bool {
	addr := ":" + strconv.Itoa(port)
	if network == "udp" {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// udpListenersIn returns local UDP ports inside [lo, hi], to avoid clashing
// with port hopping (e.g. an AmneziaWG port).
func udpListenersIn(lo, hi int) []int {
	out, err := output("ss", "-Hlnu")
	if err != nil {
		return nil
	}
	var busy []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		p, err := strconv.Atoi(local[strings.LastIndex(local, ":")+1:])
		if err == nil && p >= lo && p <= hi {
			busy = append(busy, p)
		}
	}
	return busy
}

func detectHost() (string, error) {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err == nil {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}
	out, err := output("curl", "-4fsS", "--max-time", "10", "https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("не удалось узнать внешний IP, задай --host: %v", err)
	}
	if net.ParseIP(out) == nil {
		return "", fmt.Errorf("странный ответ api.ipify.org: %q, задай --host", out)
	}
	return out, nil
}
