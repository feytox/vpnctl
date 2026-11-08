package cli

import (
	"errors"
	"os"

	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

func Logs(args []string) {
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
		a := []string{"-u", state.SubUnit, "-n", "100", "--no-pager"}
		if follow {
			a = append(a, "-f")
		}
		_ = sys.Run("journalctl", a...)
	case "", "hysteria", "hysteria-warp", "xray":
		a := []string{"logs", "--tail", "100"}
		if follow {
			a = append(a, "-f")
		}
		if svc != "" {
			a = append(a, svc)
		}
		_ = sys.Compose(a...)
	default:
		ui.Die("использование: vpnctl logs [hysteria|hysteria-warp|xray|sub] [-f]")
	}
}

func Restart() {
	state.Must()
	if err := sys.Compose("up", "-d", "--force-recreate"); err != nil {
		ui.Die("контейнеры: %v", err)
	}
	if err := sys.Run("systemctl", "restart", state.NetUnit, state.SubUnit); err != nil {
		ui.Die("systemd: %v", err)
	}
	ui.OK("перезапущено")
}

func Purge() {
	s, err := state.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		ui.Die("не читается состояние: %v", err)
	}
	if !ui.Confirm("Удалить контейнеры и образы vpnctl, правила nftables, systemd-юниты, sysctl, все ключи и клиентов? Docker останется.") {
		return
	}
	if _, err := os.Stat(state.ComposeFile()); err == nil {
		if err := sys.Compose("down", "--rmi", "all", "--remove-orphans"); err != nil {
			ui.Warn("docker compose down: %v", err)
		}
	}
	_ = sys.Run("systemctl", "disable", "--now", "-q", state.SubUnit, state.NetUnit)
	_ = sys.NetDown()
	for _, f := range []string{state.UnitDir + "/" + state.SubUnit, state.UnitDir + "/" + state.NetUnit, state.SysctlFile, state.ModulesFile} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			ui.Warn("%s: %v", f, err)
		}
	}
	_ = sys.Run("systemctl", "daemon-reload")
	if s != nil && sys.UFWActive() {
		for _, r := range s.UFWRules {
			if err := sys.Run("ufw", "delete", "allow", r); err != nil {
				ui.Warn("ufw delete allow %s: %v", r, err)
			}
		}
	}
	if err := os.RemoveAll(state.Dir); err != nil {
		ui.Warn("%s: %v", state.Dir, err)
	}
	if err := os.Remove(state.BinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		ui.Warn("%s: %v", state.BinPath, err)
	}
	ui.OK("всё удалено. Значения sysctl (BBR, буферы) держатся до перезагрузки.")
}
