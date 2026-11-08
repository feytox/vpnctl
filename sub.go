package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

func subCertPath() string { return filepath.Join(subDir(), "cert.pem") }
func subKeyPath() string  { return filepath.Join(subDir(), "key.pem") }

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
	c, err := tls.LoadX509KeyPair(subCertPath(), subKeyPath())
	if err != nil {
		return err
	}
	cs.mu.Lock()
	cs.cert = &c
	cs.mu.Unlock()
	return nil
}

// readSubCert returns the current subscription certificate, nil if there is none.
func readSubCert() *x509.Certificate {
	b, err := os.ReadFile(subCertPath())
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
func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func needRenew(c *x509.Certificate) bool {
	if c == nil || isSelfSigned(c) {
		return true
	}
	// Let's Encrypt IP certificates live ~6 days: renew at half-life.
	return time.Until(c.NotAfter) < c.NotAfter.Sub(c.NotBefore)/2
}

func serve() error {
	s, err := loadState()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(subDir(), 0o700); err != nil {
		return err
	}
	if readSubCert() == nil {
		cert, key, err := selfSigned("", net.ParseIP(s.Host), 365*24*time.Hour)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(subKeyPath(), key, 0o600); err != nil {
			return err
		}
		if err := writeFileAtomic(subCertPath(), cert, 0o644); err != nil {
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
	s, err := loadState() // re-read: add/del change the file, no restart needed
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	c := s.clientByToken(tok)
	if tok == "" || c == nil || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	log.Printf("subscription %s fetched from %s", c.Name, r.RemoteAddr)
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(s.links(c), "\n")))
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("profile-title", s.Name)
	h.Set("profile-update-interval", "12")
	_, _ = w.Write([]byte(body))
}

func renewLoop(store *certStore, host string) {
	for {
		if needRenew(readSubCert()) {
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

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// obtainIPCert gets a short-lived Let's Encrypt certificate for the IP via http-01 on port 80.
func obtainIPCert(ctx context.Context, ip string) error {
	akey, err := loadOrCreateKey(filepath.Join(subDir(), "acme-account.pem"))
	if err != nil {
		return err
	}
	cl := &acme.Client{Key: akey, DirectoryURL: envOr("VPNCTL_ACME_DIR", acme.LetsEncryptURL), UserAgent: "vpnctl"}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register: %w", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.IPIDs(ip), acme.WithOrderIssuanceProfile("shortlived"))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}

	var tokens sync.Map
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("порт 80 занят, http-01 невозможен: %w", err)
	}
	hs := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := tokens.Load(r.URL.Path); ok {
			_, _ = w.Write([]byte(v.(string)))
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()

	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			return errors.New("CA не предложил http-01")
		}
		resp, err := cl.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		tokens.Store(cl.HTTP01ChallengePath(chal.Token), resp)
		if _, err := cl.Accept(ctx, chal); err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return fmt.Errorf("authorization: %w", err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}

	ckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP(ip)}}, ckey)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kder, err := x509.MarshalECPrivateKey(ckey)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(subKeyPath()+".new", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(subCertPath()+".new", certPEM, 0o644); err != nil {
		return err
	}
	if err := os.Rename(subKeyPath()+".new", subKeyPath()); err != nil {
		return err
	}
	return os.Rename(subCertPath()+".new", subCertPath())
}
