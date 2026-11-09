// Package state keeps everything vpnctl knows about the server in one JSON
// file; every config is rendered from it.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"vpnctl/internal/gen"
	"vpnctl/internal/ui"
)

const (
	BinPath     = "/usr/local/bin/vpnctl"
	NetUnit     = "vpnctl-net.service"
	SubUnit     = "vpnctl-sub.service"
	UnitDir     = "/etc/systemd/system"
	SysctlFile  = "/etc/sysctl.d/99-vpnctl.conf"
	ModulesFile = "/etc/modules-load.d/vpnctl.conf"
	NftTable    = "vpnctl"
)

// Dir holds state.json and rendered configs; VPNCTL_STATE overrides it for tests.
var Dir = envOr("VPNCTL_STATE", "/var/lib/vpnctl")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func HysteriaDir() string { return filepath.Join(Dir, "hysteria") }
func XrayDir() string     { return filepath.Join(Dir, "xray") }
func SubDir() string      { return filepath.Join(Dir, "sub") }
func ComposeFile() string { return filepath.Join(Dir, "compose.yaml") }
func NftFile() string     { return filepath.Join(Dir, "rules.nft") }
func path() string        { return filepath.Join(Dir, "state.json") }

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
	SNI  string `json:"sni"`  // REALITY target, also sent by hysteria clients

	HyPort   int    `json:"hy_port"`
	HopRange string `json:"hop_range"` // "20000-29999", empty = no port hopping
	HyObfs   string `json:"hy_obfs"`

	XrayPort    int    `json:"xray_port"`
	RealityPriv string `json:"reality_priv"`
	RealityPub  string `json:"reality_pub"`
	XHTTPPath   string `json:"xhttp_path"`

	// gRPC is the TCP variant sing-box based clients handle well; Hiddify's XHTTP is new.
	GRPCPort    int    `json:"grpc_port"`
	GRPCService string `json:"grpc_service"`

	SubPort int `json:"sub_port"`

	UFWRules []string `json:"ufw_rules,omitempty"` // added by us, removed on purge
	Repo     string   `json:"repo,omitempty"`      // git source for `vpnctl update`
	Branch   string   `json:"branch,omitempty"`    // branch `vpnctl update` builds, empty = the clone's default

	Clients []*Client `json:"clients"`
	Relays  []*Relay  `json:"relays,omitempty"`
}

// Relay forwards local ports to another vpnctl server as is (DNAT), so clients
// that cannot reach it directly go through this one. Keys stay on the remote.
type Relay struct {
	Name string `json:"name"` // path prefix of the relayed subscription
	Host string `json:"host"` // remote IPv4

	// remote ports
	HyPort   int `json:"hy_port"`
	GRPCPort int `json:"grpc_port"`
	SubPort  int `json:"sub_port"`

	// local ports forwarded to the remote ones
	LocalHop  string `json:"local_hop"` // UDP range -> HyPort
	LocalGRPC int    `json:"local_grpc"`
}

// New returns a state with fresh secrets and default ports.
func New(subPort int) *State {
	s := &State{HyPort: 443, XrayPort: 443, SubPort: subPort}
	s.HyObfs = gen.RandHex(16)
	s.RealityPriv, s.RealityPub = gen.RealityKeys()
	s.XHTTPPath = "/" + gen.RandHex(6)
	s.Upgrade()
	return s
}

// DefaultGRPCPort is not 8443: that is the subscription port.
const DefaultGRPCPort = 2053

// Upgrade fills fields added after the state was created. It returns the
// newly assigned TCP ports, so install can check they are free.
func (s *State) Upgrade() (newPorts []int) {
	if s.GRPCPort == 0 {
		s.GRPCPort = DefaultGRPCPort
		newPorts = append(newPorts, s.GRPCPort)
	}
	if s.GRPCService == "" {
		s.GRPCService = gen.RandHex(6)
	}
	return newPorts
}

func NewClient(name string) *Client {
	return &Client{
		Name:     name,
		Created:  time.Now().UTC().Truncate(time.Second),
		HyPass:   gen.RandHex(16),
		UUID:     gen.UUID(),
		ShortID:  gen.RandHex(8),
		SubToken: gen.RandHex(16),
	}
}

var ClientNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func Load() (*State, error) {
	b, err := os.ReadFile(path())
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path(), err)
	}
	return &s, nil
}

// Must loads the state or exits with a hint.
func Must() *State {
	s, err := Load()
	if errors.Is(err, os.ErrNotExist) {
		ui.Die("vpnctl не установлен на этом сервере. Выполни: vpnctl install")
	}
	if err != nil {
		ui.Die("не читается состояние: %v", err)
	}
	return s
}

func (s *State) Save() error {
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path(), b, 0o600)
}

func (s *State) Client(name string) *Client {
	for _, c := range s.Clients {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (s *State) Relay(name string) *Relay {
	for _, r := range s.Relays {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func (s *State) ClientByToken(tok string) *Client {
	for _, c := range s.Clients {
		if c.SubToken == tok {
			return c
		}
	}
	return nil
}

// WriteFile replaces path atomically. Config dirs are bind-mounted into
// containers, so a rename inside them is seen there.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
