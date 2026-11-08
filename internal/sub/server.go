// Package sub serves subscriptions over HTTPS and keeps a Let's Encrypt
// certificate for the server IP.
package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/gen"
	"vpnctl/internal/render"
	"vpnctl/internal/state"
)

func certPath() string { return filepath.Join(state.SubDir(), "cert.pem") }
func keyPath() string  { return filepath.Join(state.SubDir(), "key.pem") }

type certStore struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func (cs *certStore) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cert, nil
}

func (cs *certStore) load() error {
	c, err := tls.LoadX509KeyPair(certPath(), keyPath())
	if err != nil {
		return err
	}
	cs.mu.Lock()
	cs.cert = &c
	cs.mu.Unlock()
	return nil
}

// ReadCert returns the current subscription certificate, nil if there is none.
func ReadCert() *x509.Certificate {
	b, err := os.ReadFile(certPath())
	if err != nil {
		return nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// CheckSignatureFrom would refuse: our self-signed certificates are not CAs.
func IsSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func needRenew(c *x509.Certificate) bool {
	if c == nil || IsSelfSigned(c) {
		return true
	}
	// Let's Encrypt IP certificates live ~6 days: renew at half-life.
	return time.Until(c.NotAfter) < c.NotAfter.Sub(c.NotBefore)/2
}

func Serve() error {
	s, err := state.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(state.SubDir(), 0o700); err != nil {
		return err
	}
	if ReadCert() == nil {
		cert, key, err := gen.SelfSigned("", net.ParseIP(s.Host), 365*24*time.Hour)
		if err != nil {
			return err
		}
		if err := state.WriteFile(keyPath(), key, 0o600); err != nil {
			return err
		}
		if err := state.WriteFile(certPath(), cert, 0o644); err != nil {
			return err
		}
	}
	store := &certStore{}
	if err := store.load(); err != nil {
		return err
	}
	go renewLoop(store, s.Host)

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(s.SubPort),
		Handler:           http.HandlerFunc(subHandler),
		TLSConfig:         &tls.Config{GetCertificate: store.get, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
	log.Printf("subscriptions on :%d", s.SubPort)
	return srv.ListenAndServeTLS("", "")
}

func subHandler(w http.ResponseWriter, r *http.Request) {
	tok := strings.Trim(r.URL.Path, "/")
	s, err := state.Load() // re-read: add/del change the file, no restart needed
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if name, rtok, ok := strings.Cut(tok, "/"); ok {
		if rl := s.Relay(name); rl != nil && rtok != "" && !strings.Contains(rtok, "/") {
			relayHandler(w, r, s, rl, rtok)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	c := s.ClientByToken(tok)
	if tok == "" || c == nil {
		http.NotFound(w, r)
		return
	}
	log.Printf("subscription %s fetched from %s", c.Name, r.RemoteAddr)
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(render.Links(s, c), "\n")))
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("profile-title", s.Name)
	h.Set("profile-update-interval", "12")
	_, _ = w.Write([]byte(body))
}

func renewLoop(store *certStore, host string) {
	for {
		if needRenew(ReadCert()) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			err := obtainIPCert(ctx, host)
			cancel()
			if err != nil {
				log.Printf("Let's Encrypt certificate for %s: %v (retry in 1h)", host, err)
			} else if err := store.load(); err != nil {
				log.Printf("load new certificate: %v", err)
			} else {
				log.Printf("Let's Encrypt certificate for %s updated", host)
			}
		}
		time.Sleep(time.Hour)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
