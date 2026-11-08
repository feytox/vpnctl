// Package sni finds and checks REALITY targets.
package sni

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/ui"
)

// Used only when the neighbour scan finds nothing.
var fallback = []string{"www.samsung.com", "dl.google.com", "www.microsoft.com"}

// Check tells whether the domain fits as a REALITY target:
// TLS 1.3, h2 and a certificate valid for the name.
func Check(name string) bool {
	d := &net.Dialer{Timeout: 4 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(name, "443"), &tls.Config{
		ServerName: name,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	st := conn.ConnectionState()
	return st.Version == tls.VersionTLS13 && st.NegotiatedProtocol == "h2"
}

// Scan looks for TLS 1.3 + h2 sites in the host's /24: a site in the same
// network as the server is the least suspicious REALITY target.
func Scan(host string, budget time.Duration) []string {
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	var (
		mu    sync.Mutex
		names = map[string]string{} // domain -> neighbour IP that served it
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 64)
	)
	for i := 1; i < 255; i++ {
		cand := net.IPv4(ip[0], ip[1], ip[2], byte(i))
		if cand.Equal(ip) {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			d := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: 3 * time.Second},
				Config: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
					MinVersion:         tls.VersionTLS13,
				},
			}
			dctx, dcancel := context.WithTimeout(ctx, 4*time.Second)
			defer dcancel()
			c, err := d.DialContext(dctx, "tcp", net.JoinHostPort(addr, "443"))
			if err != nil {
				return
			}
			defer c.Close()
			st := c.(*tls.Conn).ConnectionState()
			if st.NegotiatedProtocol != "h2" || len(st.PeerCertificates) == 0 {
				return
			}
			for _, n := range st.PeerCertificates[0].DNSNames {
				if strings.Contains(n, "*") || !strings.Contains(n, ".") {
					continue
				}
				mu.Lock()
				names[strings.ToLower(n)] = addr
				mu.Unlock()
			}
		}(cand.String())
	}
	wg.Wait()

	// A name whose DNS points back to the neighbour is a real site living in our
	// network; leftovers from old certificates and CDN names are dropped.
	var list []string
	for n, addr := range names {
		lctx, lcancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupHost(lctx, n)
		lcancel()
		if err == nil && contains(ips, addr) {
			list = append(list, n)
		}
	}
	// Plain-looking names first: fewer digits and hyphens, then shorter.
	odd := func(n string) int { return strings.Count(n, "-") + len(strings.Map(keepDigits, n)) }
	sort.Slice(list, func(i, j int) bool {
		if odd(list[i]) != odd(list[j]) {
			return odd(list[i]) < odd(list[j])
		}
		if len(list[i]) != len(list[j]) {
			return len(list[i]) < len(list[j])
		}
		return list[i] < list[j]
	})

	var good []string
	for _, n := range list {
		if Check(n) {
			good = append(good, n)
			if len(good) >= 5 {
				break
			}
		}
	}
	return good
}

func keepDigits(r rune) rune {
	if r >= '0' && r <= '9' {
		return r
	}
	return -1
}

func Pick(host string) string {
	ui.Info("ищу SNI для REALITY среди соседей %s/24 (до 40 с)", host)
	if found := Scan(host, 40*time.Second); len(found) > 0 {
		ui.OK("SNI: %s (кандидаты: %s)", found[0], strings.Join(found, ", "))
		return found[0]
	}
	ui.Warn("у соседей подходящих сайтов нет, беру из запасного списка")
	for _, n := range fallback {
		if Check(n) {
			ui.OK("SNI: %s", n)
			return n
		}
	}
	ui.Die("не нашёл SNI: ни один сайт не отвечает по TLS 1.3 + h2. Задай вручную: --sni <домен>")
	return ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
