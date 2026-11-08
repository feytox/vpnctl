// Command vpnctl installs and manages Hysteria2 + VLESS XHTTP REALITY on a VPS.
package main

import (
	"fmt"
	"os"

	"vpnctl/internal/cli"
	"vpnctl/internal/sub"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

const usage = `vpnctl - Hysteria2 + VLESS XHTTP REALITY на своём VPS, с подписками для Hiddify

Команды (нужен root, через sudo перезапускается сам):
  install [флаги]     поставить или переприменить всё (docker, конфиги, BBR, nftables, systemd)
      --host IP           внешний IPv4 (по умолчанию определяется сам)
      --name ИМЯ          имя сервера в клиентах (по умолчанию hostname)
      --sni ДОМЕН         сайт для маскировки REALITY (по умолчанию ищется среди соседей по /24)
      --hop 20000-29999   UDP-порты для port hopping, off - без него
      --sub-port 8443     TCP-порт сервера подписок (только при первой установке)
  add ИМЯ             новый клиент (устройство), печатает ссылку на подписку
  del ИМЯ             удалить клиента
  list                список клиентов
  show ИМЯ            подписка и отдельные ссылки клиента
  status              состояние контейнеров, юнитов, сертификата
  logs [hysteria|xray|sub] [-f]
  restart             пересоздать контейнеры и перезапустить юниты
  sni [ДОМЕН]         без аргумента - текущий SNI и кандидаты, с доменом - сменить
  update [--check] [--force] [--repo URL]
                      обновить vpnctl из git и переприменить всё; --check - только показать
  version             версия (коммит)
  purge               снести всё, что поставил vpnctl (docker остаётся)

Общий флаг: -y - не спрашивать подтверждений.
`

func main() {
	var args []string
	for _, a := range os.Args[1:] {
		if a == "-y" || a == "--yes" {
			ui.AssumeYes = true
			continue
		}
		args = append(args, a)
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return
	}
	cmd, rest := args[0], args[1:]
	if cmd == "version" {
		fmt.Println(cli.Version)
		return
	}

	sys.EnsureRoot()
	switch cmd {
	case "install":
		cli.Install(rest)
	case "add":
		cli.Add(rest)
	case "del", "rm":
		cli.Del(rest)
	case "list", "ls":
		cli.List()
	case "show":
		cli.Show(rest)
	case "status":
		cli.Status()
	case "logs":
		cli.Logs(rest)
	case "restart":
		cli.Restart()
	case "sni":
		cli.SNI(rest)
	case "update":
		cli.Update(rest)
	case "purge":
		cli.Purge()
	case "serve":
		if err := sub.Serve(); err != nil {
			ui.Die("%v", err)
		}
	case "net-up":
		if err := sys.NetUp(); err != nil {
			ui.Die("%v", err)
		}
	case "net-down":
		if err := sys.NetDown(); err != nil {
			ui.Die("%v", err)
		}
	default:
		ui.Die("неизвестная команда %q, см. vpnctl help", cmd)
	}
}
