package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	hysteriaImage = "tobyxdd/hysteria:v2.13.0"
	xrayImage     = "ghcr.io/xtls/xray-core:26.10.31"

	binPath     = "/usr/local/bin/vpnctl"
	netUnit     = "vpnctl-net.service"
	subUnit     = "vpnctl-sub.service"
	unitDir     = "/etc/systemd/system"
	sysctlFile  = "/etc/sysctl.d/99-vpnctl.conf"
	modulesFile = "/etc/modules-load.d/vpnctl.conf"
	nftTable    = "vpnctl"
)

var stateDir = envOr("VPNCTL_STATE", "/var/lib/vpnctl")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type Client struct {
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	HyPass   string    `json:"hy_pass"`
	UUID     string    `json:"uuid"`
	ShortID  string    `json:"short_id"`
	SubToken string    `json:"sub_token"`
}

type State struct {
	Name string `json:"name"` // label shown in client apps
	Host string `json:"host"` // public IPv4 clients connect to
	SNI  string `json:"sni"`

	HyPort   int    `json:"hy_port"`
	HopRange string `json:"hop_range"` // "20000-29999", empty = no port hopping
	HyObfs   string `json:"hy_obfs"`

	XrayPort    int    `json:"xray_port"`
	RealityPriv string `json:"reality_priv"`
	RealityPub  string `json:"reality_pub"`
	XHTTPPath   string `json:"xhttp_path"`

	SubPort int `json:"sub_port"`

	UFWRules []string `json:"ufw_rules,omitempty"` // added by us, removed on purge
	Repo     string   `json:"repo,omitempty"`      // git source for `vpnctl update`

	Clients []*Client `json:"clients"`
}

func statePath() string { return filepath.Join(stateDir, "state.json") }

func loadState() (*State, error) {
	b, err := os.ReadFile(statePath())
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", statePath(), err)
	}
	return &s, nil
}

func mustState() *State {
	s, err := loadState()
	if errors.Is(err, os.ErrNotExist) {
		die("vpnctl не установлен на этом сервере. Выполни: vpnctl install")
	}
	if err != nil {
		die("не читается состояние: %v", err)
	}
	return s
}

func (s *State) save() error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(), b, 0o600)
}

func (s *State) client(name string) *Client {
	for _, c := range s.Clients {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (s *State) clientByToken(tok string) *Client {
	for _, c := range s.Clients {
		if c.SubToken == tok {
			return c
		}
	}
	return nil
}

var clientNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
