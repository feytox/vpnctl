package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vpnctl/internal/render"
	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

const (
	warpUsage        = "использование: vpnctl warp [on [--port 8443] | off]"
	defaultWarpPort  = 8443 // UDP; the subscription server has 8443/tcp
	defaultSocksPort = 10808
)

func Warp(args []string) {
	if len(args) == 0 {
		warpStatus(state.Must())
		return
	}
	switch args[0] {
	case "on":
		warpOn(args[1:])
	case "off":
		warpOff()
	default:
		ui.Die(warpUsage)
	}
}

func warpStatus(s *state.State) {
	if s.Warp == nil {
		ui.Info("WARP выключен. Включить: vpnctl warp on")
		return
	}
	ui.KV("WARP", fmt.Sprintf("hy2 %d/udp, grpc - отдельная учётка на %d/tcp", s.Warp.HyPort, s.GRPCPort))
	ui.KV("endpoint", s.Warp.Endpoint)
}

func warpOn(args []string) {
	fs := flag.NewFlagSet("warp on", flag.ExitOnError)
	port := fs.Int("port", defaultWarpPort, "UDP-порт второго экземпляра hysteria (выход через WARP)")
	_ = fs.Parse(args)

	s := state.Must()
	if s.Warp != nil {
		ui.Info("WARP уже включён")
		warpStatus(s)
		return
	}
	if *port == s.HyPort || (s.HopRange != "" && overlaps(fmt.Sprintf("%d-%d", *port, *port), s.HopRange)) {
		ui.Die("порт %d/udp занят основным hysteria", *port)
	}
	if !sys.PortFree("udp", *port) {
		ui.Die("порт %d/udp занят, задай другой: vpnctl warp on --port N", *port)
	}
	socks := defaultSocksPort
	for !sys.PortFree("tcp", socks) {
		socks++
	}

	ui.Info("регистрирую аккаунт WARP через wgcf (сборка в %s, около минуты)", goImage)
	w, err := registerWarp()
	if err != nil {
		ui.Die("регистрация WARP: %v", err)
	}
	w.HyPort, w.SocksPort = *port, socks
	s.Warp = w
	s.Upgrade() // WARP users for clients created before WarpUUID existed
	sys.OpenPorts(s)
	applyCompose(s)
	ui.OK("WARP включён: в подписках появились записи \"%s warp hy2\" и \"%s warp grpc\"", s.Name, s.Name)
	ui.Info("Клиентам нужно обновить подписку. Проверить выход: vpnctl show <клиент>, ссылка warp, сайт ipinfo.io")
}

func warpOff() {
	s := state.Must()
	if s.Warp == nil {
		ui.Info("WARP и так выключен")
		return
	}
	if !ui.Confirm("Выключить WARP? Записи warp пропадут из подписок, аккаунт WARP будет забыт.") {
		return
	}
	sys.ClosePort(s, fmt.Sprintf("%d/udp", s.Warp.HyPort))
	s.Warp = nil
	applyCompose(s)
	ui.OK("WARP выключен")
}

// applyCompose is apply for changes that add or remove containers.
func applyCompose(s *state.State) {
	if err := s.Save(); err != nil {
		ui.Die("сохранение: %v", err)
	}
	changed, err := render.WriteServerFiles(s)
	if err != nil {
		ui.Die("конфиги: %v", err)
	}
	if err := sys.Compose("up", "-d", "--pull", "missing", "--remove-orphans"); err != nil {
		ui.Die("контейнеры: %v", err)
	}
	if len(changed) > 0 {
		if err := sys.Compose(append([]string{"restart"}, changed...)...); err != nil {
			ui.Die("перезапуск контейнеров: %v", err)
		}
	}
}

// registerWarp creates a free WARP account with wgcf and reads its WireGuard profile.
func registerWarp() (*state.Warp, error) {
	dir, err := os.MkdirTemp("", "vpnctl-warp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	err = sys.Run("docker", "run", "--rm", "-v", dir+":/w", "-w", "/w", "-e", "HOME=/tmp", goImage, "sh", "-c",
		"go install "+state.Wgcf+" && /go/bin/wgcf register --accept-tos && /go/bin/wgcf generate")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, "wgcf-profile.conf"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	w := &state.Warp{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "PrivateKey":
			w.PrivateKey = v
		case "PublicKey":
			w.PeerPublicKey = v
		case "Endpoint":
			w.Endpoint = v
		case "Address":
			for _, a := range strings.Split(v, ",") {
				w.Address = append(w.Address, strings.TrimSpace(a))
			}
		}
	}
	if w.PrivateKey == "" || w.PeerPublicKey == "" || w.Endpoint == "" || len(w.Address) == 0 {
		return nil, fmt.Errorf("в профиле wgcf не хватает полей")
	}
	return w, nil
}
