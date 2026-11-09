package sys

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"vpnctl/internal/ui"
)

const detachedEnv = "VPNCTL_DETACHED"

func Detach(unit string) {
	if os.Getenv(detachedEnv) != "" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		ui.Die("%v", err)
	}
	follow := exec.Command("journalctl", "-f", "-n", "all", "-o", "cat",
		fmt.Sprintf("--since=@%d", time.Now().Unix()), "_SYSTEMD_UNIT="+unit+".service")
	follow.Stdout, follow.Stderr = os.Stdout, os.Stderr
	if err := follow.Start(); err != nil {
		ui.Die("journalctl: %v", err)
	}
	ui.Info("%sвыполняется в фоне (%s): если связь оборвётся, команда доработает сама, вывод - journalctl -u %s%s",
		ui.Dim, unit, unit, ui.Reset)
	args := []string{"--unit=" + unit, "--wait", "--quiet", "--collect", "--service-type=exec",
		"--setenv=" + detachedEnv + "=1", "--setenv=SUDO_USER=" + os.Getenv("SUDO_USER"), self, "-y"}
	run := exec.Command("systemd-run", append(args, os.Args[1:]...)...)
	run.Stderr = os.Stderr
	err = run.Run()
	time.Sleep(time.Second)
	_ = follow.Process.Kill()
	_ = follow.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	if err != nil {
		ui.Die("systemd-run: %v", err)
	}
	os.Exit(0)
}
