package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"vpnctl/internal/gen"
	"vpnctl/internal/sni"
	"vpnctl/internal/state"
	"vpnctl/internal/ui"
)

// Rotate changes what a censor could have fingerprinted: the salamander
// password and the SNI. Clients get both with the next subscription update.
func Rotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	sniFlag := fs.String("sni", "", "новый SNI (по умолчанию ищется другой среди соседей)")
	keepSNI := fs.Bool("keep-sni", false, "сменить только obfs")
	_ = fs.Parse(args)

	s := state.Must()
	newSNI := s.SNI
	switch {
	case *keepSNI:
	case *sniFlag != "":
		newSNI = strings.ToLower(*sniFlag)
		if !sni.Check(newSNI) && !ui.Confirm(fmt.Sprintf("%s не отвечает по TLS 1.3 + h2 с этого сервера. Всё равно взять?", newSNI)) {
			os.Exit(1)
		}
	default:
		if newSNI = sni.Other(s.Host, s.SNI); newSNI == "" {
			ui.Warn("другого подходящего SNI нет, оставляю %s", s.SNI)
			newSNI = s.SNI
		}
	}

	ui.KV("SNI", fmt.Sprintf("%s -> %s", s.SNI, newSNI))
	ui.KV("obfs hy2", "новый пароль")
	if !ui.Confirm("Старые настройки перестанут работать сразу. Клиенты подключатся снова только после обновления подписки. Продолжить?") {
		return
	}
	s.SNI = newSNI
	s.HyObfs = gen.RandHex(16)
	apply(s)
	ui.OK("готово. В Hiddify обнови подписку вручную (сама обновится в течение 12 ч)")
}
