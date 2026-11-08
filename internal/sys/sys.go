// Package sys does the host side: commands, docker, sysctl, nftables,
// systemd units and ufw.
package sys

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"vpnctl/internal/state"
	"vpnctl/internal/ui"
)

func Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func Output(name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && errb.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), err
}

func Have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func Compose(args ...string) error {
	return Run("docker", append([]string{"compose", "-f", state.ComposeFile()}, args...)...)
}

func ComposeOut(args ...string) (string, error) {
	return Output("docker", append([]string{"compose", "-f", state.ComposeFile()}, args...)...)
}

// ensureRoot re-runs the command through sudo when needed.
func EnsureRoot() {
	if os.Geteuid() == 0 {
		return
	}
	self, err := os.Executable()
	if err != nil {
		ui.Die("нужен root: %v", err)
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		ui.Die("нужен root, а sudo не найден")
	}
	cmd := exec.Command(sudo, append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		ui.Die("%v", err)
	}
	os.Exit(0)
}

func AptInstall(pkgs ...string) error {
	if !Have("apt-get") {
		return fmt.Errorf("нет apt-get, поставь вручную: %s", strings.Join(pkgs, " "))
	}
	cmd := exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		_ = Run("apt-get", "update", "-q")
		cmd = exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	return nil
}

func EnsureDocker() {
	if Have("docker") {
		if _, err := Output("docker", "compose", "version"); err != nil {
			ui.Info("ставлю docker compose plugin")
			if err := AptInstall("docker-compose-plugin"); err != nil {
				ui.Die("нет docker compose: %v", err)
			}
		}
		return
	}
	if !ui.Confirm("Docker не установлен. Поставить через get.docker.com?") {
		ui.Die("без docker не получится")
	}
	if !Have("curl") {
		if err := AptInstall("curl"); err != nil {
			ui.Die("%v", err)
		}
	}
	if err := Run("sh", "-c", "curl -fsSL https://get.docker.com | sh"); err != nil {
		ui.Die("установка docker не удалась: %v", err)
	}
	_ = Run("systemctl", "enable", "--now", "docker")
}

func EnsureNft() {
	if Have("nft") {
		return
	}
	ui.Info("ставлю nftables")
	if err := AptInstall("nftables"); err != nil {
		ui.Die("%v", err)
	}
}

// MPTCP is off because Go 1.24+ listens with it by default and an MPTCP kernel
// hole gives remote root; newer Xray turns it off itself, the pinned one does not.
const sysctlConf = `# vpnctl: BBR for TCP from the server, bigger UDP buffers for QUIC, no MPTCP, forwarding for relays
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.mptcp.enabled = 0
net.ipv4.ip_forward = 1
`

func ApplySysctl() error {
	if err := os.WriteFile(state.ModulesFile, []byte("tcp_bbr\n"), 0o644); err != nil {
		return err
	}
	_ = Run("modprobe", "tcp_bbr")
	if err := os.WriteFile(state.SysctlFile, []byte(sysctlConf), 0o644); err != nil {
		return err
	}
	// -e: kernels without MPTCP have no net.mptcp.enabled
	_, err := Output("sysctl", "-e", "-p", state.SysctlFile)
	return err
}

func NftRules(s *state.State) string {
	var b strings.Builder
	// the empty definition makes delete safe when the table does not exist yet
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", state.NftTable, state.NftTable)
	fmt.Fprintf(&b, "table inet %s {\n", state.NftTable)
	b.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	if s.HopRange != "" {
		fmt.Fprintf(&b, "    udp dport %s redirect to :%d\n", s.HopRange, s.HyPort)
	}
	// fib: only packets addressed to this host, not container traffic passing through
	for _, r := range s.Relays {
		fmt.Fprintf(&b, "    meta nfproto ipv4 fib daddr type local udp dport %s dnat ip to %s:%d\n", r.LocalHop, r.Host, r.HyPort)
		fmt.Fprintf(&b, "    meta nfproto ipv4 fib daddr type local tcp dport %d dnat ip to %s:%d\n", r.LocalGRPC, r.Host, r.GRPCPort)
	}
	b.WriteString("  }\n")
	if len(s.Relays) > 0 {
		// the remote must answer through us, so it has to see our address
		b.WriteString("  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
		for _, r := range s.Relays {
			fmt.Fprintf(&b, "    ip daddr %s ct status dnat masquerade\n", r.Host)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func NetUp() error {
	s, err := state.Load()
	if err != nil {
		return err
	}
	if err := state.WriteFile(state.NftFile(), []byte(NftRules(s)), 0o600); err != nil {
		return err
	}
	if _, err = Output("nft", "-f", state.NftFile()); err != nil {
		return err
	}
	return allowForward(s.Relays)
}

const fwdComment = "vpnctl"

// forwardChain is where relayed packets have to be accepted: Docker sets the
// iptables FORWARD policy to DROP and leaves DOCKER-USER to the admin. An nft
// accept in our own table would not help, every hook has to accept.
func forwardChain() string {
	if _, err := Output("iptables", "-n", "-L", "DOCKER-USER"); err == nil {
		return "DOCKER-USER"
	}
	return "FORWARD"
}

// allowForward replaces our iptables rules with ones for the given relays.
func allowForward(relays []*state.Relay) error {
	if !Have("iptables") {
		return nil
	}
	if err := dropForwardRules(); err != nil {
		return err
	}
	chain := forwardChain()
	for _, r := range relays {
		for _, dir := range []string{"-d", "-s"} {
			if _, err := Output("iptables", "-I", chain, dir, r.Host, "-m", "conntrack", "--ctstate", "DNAT",
				"-m", "comment", "--comment", fwdComment, "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("iptables %s: %w", chain, err)
			}
		}
	}
	return nil
}

func dropForwardRules() error {
	for _, chain := range []string{"DOCKER-USER", "FORWARD"} {
		out, err := Output("iptables", "-S", chain)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "-A" || !strings.Contains(line, "--comment "+fwdComment+" ") {
				continue
			}
			f[0] = "-D"
			if _, err := Output("iptables", f...); err != nil {
				return fmt.Errorf("iptables %s: %w", strings.Join(f, " "), err)
			}
		}
	}
	return nil
}

func NetDown() error {
	if Have("iptables") {
		if err := dropForwardRules(); err != nil {
			return err
		}
	}
	if _, err := Output("nft", "list", "table", "inet", state.NftTable); err != nil {
		return nil
	}
	_, err := Output("nft", "delete", "table", "inet", state.NftTable)
	return err
}

func netUnitText() string {
	return fmt.Sprintf(`[Unit]
Description=vpnctl nftables rules (port hopping, relays)
After=network-pre.target nftables.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%[1]s net-up
ExecStop=%[1]s net-down

[Install]
WantedBy=multi-user.target
`, state.BinPath)
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
`, state.BinPath)
}

func InstallUnits() error {
	for name, text := range map[string]string{state.NetUnit: netUnitText(), state.SubUnit: subUnitText()} {
		if err := os.WriteFile(filepath.Join(state.UnitDir, name), []byte(text), 0o644); err != nil {
			return err
		}
	}
	if err := Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := Run("systemctl", "enable", "-q", state.NetUnit, state.SubUnit); err != nil {
		return err
	}
	if err := Run("systemctl", "restart", state.NetUnit); err != nil {
		return err
	}
	return Run("systemctl", "restart", state.SubUnit)
}

// copySelf puts the running binary to state.BinPath so systemd units can use it.
func CopySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self == state.BinPath {
		return nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return state.WriteFile(state.BinPath, data, 0o755)
}

func UFWActive() bool {
	if !Have("ufw") {
		return false
	}
	out, err := Output("ufw", "status")
	return err == nil && strings.HasPrefix(out, "Status: active")
}

// openPorts adds ufw rules when ufw is active. Port hopping needs no rules:
// the redirect happens in prerouting, before the input filter sees the packet.
func OpenPorts(s *state.State) {
	if !UFWActive() {
		return
	}
	want := []string{
		fmt.Sprintf("%d/udp", s.HyPort),
		fmt.Sprintf("%d/tcp", s.XrayPort),
		fmt.Sprintf("%d/tcp", s.GRPCPort),
		fmt.Sprintf("%d/tcp", s.SubPort),
		"80/tcp", // ACME http-01 for the subscription certificate
	}
	if s.Warp != nil {
		want = append(want, fmt.Sprintf("%d/udp", s.Warp.HyPort))
	}
	status, _ := Output("ufw", "status")
	for _, r := range want {
		if Contains(s.UFWRules, r) || ufwHas(status, r) {
			continue // a rule the user had before stays theirs, purge will not touch it
		}
		if err := Run("ufw", "allow", r); err != nil {
			ui.Warn("ufw allow %s: %v", r, err)
			continue
		}
		s.UFWRules = append(s.UFWRules, r)
	}
}

// ClosePort removes a ufw rule vpnctl added earlier.
func ClosePort(s *state.State, rule string) {
	if !Contains(s.UFWRules, rule) {
		return
	}
	if UFWActive() {
		if err := Run("ufw", "delete", "allow", rule); err != nil {
			ui.Warn("ufw delete allow %s: %v", rule, err)
			return
		}
	}
	var keep []string
	for _, r := range s.UFWRules {
		if r != rule {
			keep = append(keep, r)
		}
	}
	s.UFWRules = keep
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

func Contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func PortFree(network string, port int) bool {
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
func UDPListenersIn(lo, hi int) []int {
	out, err := Output("ss", "-Hlnu")
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

func DetectHost() (string, error) {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err == nil {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}
	out, err := Output("curl", "-4fsS", "--max-time", "10", "https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("не удалось узнать внешний IP, задай --host: %v", err)
	}
	if net.ParseIP(out) == nil {
		return "", fmt.Errorf("странный ответ api.ipify.org: %q, задай --host", out)
	}
	return out, nil
}
