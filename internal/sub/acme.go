package sub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"vpnctl/internal/state"
)

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
	return k, state.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// obtainIPCert gets a short-lived Let's Encrypt certificate for the IP via http-01 on port 80.
func obtainIPCert(ctx context.Context, ip string) error {
	akey, err := loadOrCreateKey(filepath.Join(state.SubDir(), "acme-account.pem"))
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
	if err := state.WriteFile(keyPath()+".new", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	if err := state.WriteFile(certPath()+".new", certPEM, 0o644); err != nil {
		return err
	}
	if err := os.Rename(keyPath()+".new", keyPath()); err != nil {
		return err
	}
	return os.Rename(certPath()+".new", certPath())
}
