package main

import (
	"fmt"
	"os"
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
			assumeYes = true
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
		fmt.Println(version)
		return
	}

	ensureRoot()
	switch cmd {
	case "install":
		cmdInstall(rest)
	case "add":
		cmdAdd(rest)
	case "del", "rm":
		cmdDel(rest)
	case "list", "ls":
		cmdList()
	case "show":
		cmdShow(rest)
	case "status":
		cmdStatus()
	case "logs":
		cmdLogs(rest)
	case "restart":
		cmdRestart()
	case "sni":
		cmdSNI(rest)
	case "update":
		cmdUpdate(rest)
	case "purge":
		cmdPurge()
	case "serve":
		if err := serve(); err != nil {
			die("%v", err)
		}
	case "net-up":
		if err := netUp(); err != nil {
			die("%v", err)
		}
	case "net-down":
		if err := netDown(); err != nil {
			die("%v", err)
		}
	default:
		die("неизвестная команда %q, см. vpnctl help", cmd)
	}
}
