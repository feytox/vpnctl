package cli

import (
	"fmt"

	"vpnctl/internal/render"
	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

func applyClients(s *state.State) {
	if err := s.Save(); err != nil {
		ui.Die("сохранение: %v", err)
	}
	if err := render.WriteServerFiles(s); err != nil {
		ui.Die("конфиги: %v", err)
	}
	if composeRunning() {
		if err := sys.Compose("restart", "hysteria", "xray"); err != nil {
			ui.Die("перезапуск контейнеров: %v", err)
		}
	} else {
		ui.Warn("контейнеры не запущены, изменения применятся при старте: vpnctl restart")
	}
}

func Add(args []string) {
	if len(args) != 1 {
		ui.Die("использование: vpnctl add <имя>")
	}
	name := args[0]
	if !state.ClientNameRe.MatchString(name) {
		ui.Die("имя: латиница в нижнем регистре, цифры, - и _, до 32 символов")
	}
	s := state.Must()
	if s.Client(name) != nil {
		ui.Die("клиент %s уже есть. Ссылка: vpnctl show %s", name, name)
	}
	c := state.NewClient(name)
	s.Clients = append(s.Clients, c)
	applyClients(s)
	ui.OK("клиент %s добавлен", name)
	printClient(s, c, false)
}

func Del(args []string) {
	if len(args) != 1 {
		ui.Die("использование: vpnctl del <имя>")
	}
	s := state.Must()
	if s.Client(args[0]) == nil {
		ui.Die("клиента %s нет", args[0])
	}
	if !ui.Confirm(fmt.Sprintf("Удалить клиента %s? Его подписка и ключи перестанут работать.", args[0])) {
		return
	}
	var keep []*state.Client
	for _, c := range s.Clients {
		if c.Name != args[0] {
			keep = append(keep, c)
		}
	}
	s.Clients = keep
	applyClients(s)
	ui.OK("клиент %s удалён", args[0])
}

func List() {
	s := state.Must()
	if len(s.Clients) == 0 {
		ui.Info("клиентов нет. Добавь: vpnctl add <имя>")
		return
	}
	fmt.Printf("%-20s %s\n", "ИМЯ", "СОЗДАН")
	for _, c := range s.Clients {
		fmt.Printf("%-20s %s\n", c.Name, c.Created.Local().Format("2006-01-02 15:04"))
	}
}

func Show(args []string) {
	if len(args) != 1 {
		ui.Die("использование: vpnctl show <имя>")
	}
	s := state.Must()
	c := s.Client(args[0])
	if c == nil {
		ui.Die("клиента %s нет", args[0])
	}
	printClient(s, c, true)
}

func printClient(s *state.State, c *state.Client, withLinks bool) {
	ui.Header("Подписка " + c.Name)
	ui.Info("%s", render.SubURL(s, c))
	ui.Info("%sHiddify: + -> Добавить из буфера обмена. Обновляется сама раз в 12 ч.%s", ui.Dim, ui.Reset)
	if withLinks {
		ui.Header("Ссылки по отдельности")
		for _, l := range render.Links(s, c) {
			ui.Info("%s", l)
		}
	}
}
