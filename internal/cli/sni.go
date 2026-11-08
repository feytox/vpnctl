package cli

import (
	"fmt"
	"strings"
	"time"

	"vpnctl/internal/render"
	"vpnctl/internal/sni"
	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

func SNI(args []string) {
	s := state.Must()
	if len(args) == 0 {
		ui.KV("сейчас", s.SNI)
		ui.Info("ищу кандидатов среди соседей %s/24 (до 40 с)", s.Host)
		found := sni.Scan(s.Host, 40*time.Second)
		if len(found) == 0 {
			ui.Warn("подходящих соседей нет")
			return
		}
		for _, n := range found {
			ui.Info("  %s", n)
		}
		ui.Info("сменить: vpnctl sni <домен>")
		return
	}
	name := strings.ToLower(args[0])
	if !sni.Check(name) && !ui.Confirm(fmt.Sprintf("%s не отвечает по TLS 1.3 + h2 с этого сервера. Всё равно взять?", name)) {
		return
	}
	s.SNI = name
	if err := s.Save(); err != nil {
		ui.Die("%v", err)
	}
	if err := render.WriteServerFiles(s); err != nil {
		ui.Die("%v", err)
	}
	if err := sys.Compose("up", "-d", "--force-recreate", "xray"); err != nil {
		ui.Die("%v", err)
	}
	ui.OK("SNI теперь %s. Клиентам нужно обновить подписку (Hiddify сам раз в 12 ч или вручную)", name)
}
