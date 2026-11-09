package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpnctl/internal/state"
	"vpnctl/internal/sys"
	"vpnctl/internal/ui"
)

// Version is the git commit the binary was built from, set by `vpnctl update`.
var Version = "dev"

const (
	defaultRepo = "https://github.com/feytox/vpnctl.git"
	goImage     = "golang:1.27-alpine"
)

// The source is cloned and pulled as the user who ran sudo: their git
// credentials (ssh key or gh) work, root's usually are not set up.
type srcUser struct {
	name     string
	uid, gid string
	dir      string
}

func sourceUser() srcUser {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = "root"
	}
	u, err := user.Lookup(name)
	if err != nil {
		ui.Die("пользователь %s: %v", name, err)
	}
	return srcUser{name, u.Uid, u.Gid, filepath.Join(u.HomeDir, ".local/share/vpnctl/src")}
}

func (u srcUser) git(args ...string) (string, error) {
	full := append([]string{"-u", u.name, "-H", "git", "-C", u.dir}, args...)
	return sys.Output("sudo", full...)
}

func (u srcUser) cloned() bool {
	_, err := os.Stat(filepath.Join(u.dir, ".git"))
	return err == nil
}

var imageRe = regexp.MustCompile(`(HysteriaImage|XrayImage)\s*=\s*"([^"]+)"`)

func pinnedImages(src string) map[string]string {
	m := map[string]string{}
	for _, g := range imageRe.FindAllStringSubmatch(src, -1) {
		m[g[1]] = g[2]
	}
	return m
}

func latestRelease(repo string) string {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var r struct {
		Tag string `json:"tag_name"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&r) != nil {
		return ""
	}
	return r.Tag
}

func tagOf(image string) string { return image[strings.LastIndex(image, ":")+1:] }

func Update(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "только показать, что обновится")
	force := fs.Bool("force", false, "пересобрать и переприменить, даже если новых коммитов нет")
	repo := fs.String("repo", "", "git-репозиторий vpnctl (запоминается)")
	branch := fs.String("branch", "", "ветка, из которой собирать (запоминается)")
	_ = fs.Parse(args)
	if !*check {
		sys.Detach("vpnctl-update")
	}

	if *check && *repo != "" {
		ui.Die("--repo с --check не сочетается: --check ничего не меняет")
	}
	if !sys.Have("git") {
		if err := sys.AptInstall("git"); err != nil {
			ui.Die("%v", err)
		}
	}
	if *branch != "" {
		if _, err := sys.Output("git", "check-ref-format", "--branch", *branch); err != nil {
			ui.Die("некорректное имя ветки: %q", *branch)
		}
	}

	s := state.Must()
	if *repo != "" {
		s.Repo = *repo
	}
	if *branch != "" {
		s.Branch = *branch
	}
	if !*check && (*repo != "" || *branch != "") {
		if err := s.Save(); err != nil {
			ui.Die("%v", err)
		}
	}
	if s.Repo == "" {
		s.Repo = defaultRepo
	}

	u := sourceUser()
	if !u.cloned() {
		ui.Info("клонирую %s в %s (от имени %s)", s.Repo, u.dir, u.name)
		if err := os.MkdirAll(filepath.Dir(u.dir), 0o755); err != nil {
			ui.Die("%v", err)
		}
		_ = os.Chown(filepath.Dir(u.dir), atoi(u.uid), atoi(u.gid))
		if err := sys.Run("sudo", "-u", u.name, "-H", "git", "clone", "-q", s.Repo, u.dir); err != nil {
			ui.Die("git clone %s: %v. Другой репозиторий: vpnctl update --repo URL", s.Repo, err)
		}
	} else {
		if *repo != "" {
			if _, err := u.git("remote", "set-url", "origin", *repo); err != nil {
				ui.Die("git remote set-url: %v", err)
			}
		}
		if _, err := u.git("fetch", "-q", "--prune", "origin"); err != nil {
			ui.Die("git fetch: %v", err)
		}
	}
	cur, _ := u.git("rev-parse", "--abbrev-ref", "HEAD")
	br := s.Branch
	if br == "" {
		br = cur
	}
	target := "origin/" + br
	remote, err := u.git("rev-parse", "--short", target)
	if err != nil {
		ui.Die("ветки %s нет в %s (вернуться на main: vpnctl update --branch main)", br, s.Repo)
	}
	if !*check && br != cur {
		if _, err := u.git("switch", "-q", br); err != nil {
			ui.Die("git switch %s: %v", br, err)
		}
	}

	ui.Header("vpnctl")
	ui.KV("установлен", Version)
	ui.KV("в репозитории", remote)
	ui.KV("ветка", br)
	installed, _ := u.git("rev-parse", "--verify", "-q", Version+"^{commit}")
	targetHash, _ := u.git("rev-parse", target)
	upToDate := installed != "" && installed == targetHash
	if !upToDate && installed != "" {
		if log, err := u.git("log", "--oneline", "--no-decorate", Version+".."+target); err == nil && log != "" {
			for _, l := range strings.Split(log, "\n") {
				ui.Info("    %s", l)
			}
		}
	}

	ui.Header("Образы")
	newSrc, _ := u.git("show", target+":internal/state/versions.go")
	next := pinnedImages(newSrc)
	for _, k := range []struct{ key, cur, upstream, prefix, hold string }{
		{"HysteriaImage", state.HysteriaImage, "apernet/hysteria", "app/", ""},
		{"XrayImage", state.XrayImage, "XTLS/Xray-core", "v", state.XrayHold},
	} {
		line := k.cur
		if n := next[k.key]; n != "" && n != k.cur {
			line += " -> " + n
		}
		if latest := strings.TrimPrefix(latestRelease(k.upstream), k.prefix); latest != "" &&
			strings.TrimPrefix(tagOf(k.cur), "v") != strings.TrimPrefix(latest, "v") &&
			strings.TrimPrefix(tagOf(next[k.key]), "v") != strings.TrimPrefix(latest, "v") {
			why := "в vpnctl ещё не закреплён"
			if k.hold != "" {
				why = "держим старый: " + k.hold
			}
			line += fmt.Sprintf("  %s(upstream: %s, %s)%s", ui.Yellow, latest, why, ui.Reset)
		}
		ui.KV(strings.ToLower(strings.TrimSuffix(k.key, "Image")), line)
	}

	if *check {
		return
	}
	if upToDate && !*force {
		ui.OK("обновлять нечего (переприменить всё равно: vpnctl update --force)")
		return
	}
	if !upToDate {
		if _, err := u.git("merge", "-q", "--ff-only", target); err != nil {
			ui.Die("git merge --ff-only: %v (в %s есть локальные изменения?)", err, u.dir)
		}
	}
	head, _ := u.git("rev-parse", "--short", "HEAD")
	ui.Info("собираю %s в %s", head, goImage)
	cache := filepath.Join(filepath.Dir(u.dir), "gocache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		ui.Die("%v", err)
	}
	_ = os.Chown(cache, atoi(u.uid), atoi(u.gid))
	out := filepath.Join(u.dir, "vpnctl.new")
	err = sys.Run("docker", "run", "--rm", "--user", u.uid+":"+u.gid,
		"-v", u.dir+":/src", "-v", cache+":/cache", "-w", "/src",
		"-e", "CGO_ENABLED=0", "-e", "HOME=/tmp", "-e", "GOCACHE=/cache/build", "-e", "GOMODCACHE=/cache/mod",
		goImage, "go", "build", "-trimpath", "-ldflags", "-s -w -X vpnctl/internal/cli.Version="+head, "-o", "/src/vpnctl.new", "./cmd/vpnctl")
	if err != nil {
		ui.Die("сборка не удалась, установленная версия не тронута")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		ui.Die("%v", err)
	}
	_ = os.Remove(out)
	if err := state.WriteFile(state.BinPath, data, 0o755); err != nil {
		ui.Die("%v", err)
	}
	ui.OK("vpnctl %s установлен, переприменяю конфигурацию", head)
	// the new binary re-applies everything: configs, units, images
	if err := syscall.Exec(state.BinPath, []string{state.BinPath, "-y", "install"}, os.Environ()); err != nil {
		ui.Die("запуск нового бинарника: %v", err)
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}
