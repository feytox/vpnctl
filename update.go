package main

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
)

// version is the git commit the binary was built from, set by `vpnctl update`.
var version = "dev"

const (
	defaultRepo = "https://github.com/Feytox/vpnctl.git"
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
		die("пользователь %s: %v", name, err)
	}
	return srcUser{name, u.Uid, u.Gid, filepath.Join(u.HomeDir, ".local/share/vpnctl/src")}
}

func (u srcUser) git(args ...string) (string, error) {
	full := append([]string{"-u", u.name, "-H", "git", "-C", u.dir}, args...)
	return output("sudo", full...)
}

func (u srcUser) cloned() bool {
	_, err := os.Stat(filepath.Join(u.dir, ".git"))
	return err == nil
}

var imageRe = regexp.MustCompile(`(hysteriaImage|xrayImage)\s*=\s*"([^"]+)"`)

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

func cmdUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "только показать, что обновится")
	force := fs.Bool("force", false, "пересобрать и переприменить, даже если новых коммитов нет")
	repo := fs.String("repo", "", "git-репозиторий vpnctl (запоминается)")
	_ = fs.Parse(args)

	s := mustState()
	if *repo != "" {
		s.Repo = *repo
		if err := s.save(); err != nil {
			die("%v", err)
		}
	}
	if s.Repo == "" {
		s.Repo = defaultRepo
	}
	if !have("git") {
		if err := aptInstall("git"); err != nil {
			die("%v", err)
		}
	}

	u := sourceUser()
	if !u.cloned() {
		info("клонирую %s в %s (от имени %s)", s.Repo, u.dir, u.name)
		if err := os.MkdirAll(filepath.Dir(u.dir), 0o755); err != nil {
			die("%v", err)
		}
		_ = os.Chown(filepath.Dir(u.dir), atoi(u.uid), atoi(u.gid))
		if err := run("sudo", "-u", u.name, "-H", "git", "clone", "-q", s.Repo, u.dir); err != nil {
			die("git clone не удался. Если репозиторий по ssh, задай: vpnctl update --repo git@github.com:Feytox/vpnctl.git")
		}
	} else if _, err := u.git("fetch", "-q", "origin"); err != nil {
		die("git fetch: %v", err)
	}
	remote, err := u.git("rev-parse", "--short", "@{u}")
	if err != nil {
		die("git: %v", err)
	}

	header("vpnctl")
	kv("установлен", version)
	kv("в репозитории", remote)
	upToDate := version == remote
	if !upToDate && version != "dev" {
		if log, err := u.git("log", "--oneline", "--no-decorate", version+"..@{u}"); err == nil && log != "" {
			for _, l := range strings.Split(log, "\n") {
				info("    %s", l)
			}
		}
	}

	header("Образы")
	newSrc, _ := u.git("show", "@{u}:state.go")
	next := pinnedImages(newSrc)
	for _, k := range []struct{ key, cur, upstream, prefix string }{
		{"hysteriaImage", hysteriaImage, "apernet/hysteria", "app/"},
		{"xrayImage", xrayImage, "XTLS/Xray-core", "v"},
	} {
		line := k.cur
		if n := next[k.key]; n != "" && n != k.cur {
			line += " -> " + n
		}
		if latest := strings.TrimPrefix(latestRelease(k.upstream), k.prefix); latest != "" &&
			strings.TrimPrefix(tagOf(k.cur), "v") != strings.TrimPrefix(latest, "v") &&
			strings.TrimPrefix(tagOf(next[k.key]), "v") != strings.TrimPrefix(latest, "v") {
			line += fmt.Sprintf("  %s(upstream: %s, в vpnctl ещё не закреплён)%s", cYellow, latest, cReset)
		}
		kv(strings.TrimSuffix(k.key, "Image"), line)
	}

	if *check {
		return
	}
	if upToDate && !*force {
		ok("обновлять нечего (переприменить всё равно: vpnctl update --force)")
		return
	}
	if !upToDate {
		if _, err := u.git("merge", "-q", "--ff-only", "@{u}"); err != nil {
			die("git merge --ff-only: %v (в %s есть локальные изменения?)", err, u.dir)
		}
	}
	head, _ := u.git("rev-parse", "--short", "HEAD")
	info("собираю %s в %s", head, goImage)
	cache := filepath.Join(filepath.Dir(u.dir), "gocache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		die("%v", err)
	}
	_ = os.Chown(cache, atoi(u.uid), atoi(u.gid))
	out := filepath.Join(u.dir, "vpnctl.new")
	err = run("docker", "run", "--rm", "--user", u.uid+":"+u.gid,
		"-v", u.dir+":/src", "-v", cache+":/cache", "-w", "/src",
		"-e", "CGO_ENABLED=0", "-e", "HOME=/tmp", "-e", "GOCACHE=/cache/build", "-e", "GOMODCACHE=/cache/mod",
		goImage, "go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+head, "-o", "/src/vpnctl.new", ".")
	if err != nil {
		die("сборка не удалась, установленная версия не тронута")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		die("%v", err)
	}
	_ = os.Remove(out)
	if err := writeFileAtomic(binPath, data, 0o755); err != nil {
		die("%v", err)
	}
	ok("vpnctl %s установлен, переприменяю конфигурацию", head)
	// the new binary re-applies everything: configs, units, images
	if err := syscall.Exec(binPath, []string{binPath, "-y", "install"}, os.Environ()); err != nil {
		die("запуск нового бинарника: %v", err)
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func cmdSNI(args []string) {
	s := mustState()
	if len(args) == 0 {
		kv("сейчас", s.SNI)
		info("ищу кандидатов среди соседей %s/24 (до 40 с)", s.Host)
		found := scanSNI(s.Host, 40*time.Second)
		if len(found) == 0 {
			warn("подходящих соседей нет")
			return
		}
		for _, n := range found {
			info("  %s", n)
		}
		info("сменить: vpnctl sni <домен>")
		return
	}
	name := strings.ToLower(args[0])
	if !checkSNI(name) && !confirm(fmt.Sprintf("%s не отвечает по TLS 1.3 + h2 с этого сервера. Всё равно взять?", name)) {
		return
	}
	s.SNI = name
	if err := s.save(); err != nil {
		die("%v", err)
	}
	if err := s.writeServerFiles(); err != nil {
		die("%v", err)
	}
	if err := compose("up", "-d", "--force-recreate", "xray"); err != nil {
		die("%v", err)
	}
	ok("SNI теперь %s. Клиентам нужно обновить подписку (Hiddify сам раз в 12 ч или вручную)", name)
}
