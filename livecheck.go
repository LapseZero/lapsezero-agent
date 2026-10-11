package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// reload 是异步的，worker 换上新配置需要一点时间
	liveCheckWindow   = 15 * time.Second
	liveCheckInterval = time.Second
	liveCheckTimeout  = 5 * time.Second
)

// 与平台 agentResultSchema 中的 liveCheck 一致
type liveCheck struct {
	Status     string     `json:"status"` // VERIFIED | MISMATCH | UNREACHABLE
	Address    string     `json:"address"`
	ServerName string     `json:"serverName,omitempty"`
	Subject    string     `json:"subject,omitempty"`
	Issuer     string     `json:"issuer,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	ErrorCode  string     `json:"errorCode,omitempty"`
}

type liveProbe struct {
	address    string
	serverName string
	expected   [32]byte
}

// checkLive 在本机连接使用这些证书文件的 Nginx 站点，确认返回的是刚写入的证书。
// 没有 Nginx 或没有站点引用这些文件时返回 nil，表示无从检查。
func checkLive(files []fileSpec) *liveCheck {
	bin := findNginx()
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-T").Output()
	if err != nil {
		return nil
	}
	pairs := parseNginxDump(out)

	var probes []liveProbe
	for _, f := range files {
		leaf := leafCertificate(f.Content)
		if leaf == nil {
			continue
		}
		for _, p := range pairs {
			if p.certPath != filepath.Clean(f.Path) {
				continue
			}
			sni := probeServerName(p.serverNames)
			for _, a := range p.listens {
				probes = append(probes, liveProbe{address: a, serverName: sni, expected: sha256.Sum256(leaf.Raw)})
			}
		}
	}
	if len(probes) == 0 {
		return nil
	}
	return waitLive(probes)
}

func waitLive(probes []liveProbe) *liveCheck {
	deadline := time.Now().Add(liveCheckWindow)
	for {
		r := runProbes(probes)
		if r.Status == "VERIFIED" || time.Now().Add(liveCheckInterval).After(deadline) {
			return r
		}
		time.Sleep(liveCheckInterval)
	}
}

// 全部地址都是新证书才算生效，否则返回第一个不符的结果
func runProbes(probes []liveProbe) *liveCheck {
	var first *liveCheck
	for _, p := range probes {
		r := p.run()
		if r.Status != "VERIFIED" {
			return r
		}
		if first == nil {
			first = r
		}
	}
	return first
}

func (p liveProbe) run() *liveCheck {
	r := &liveCheck{Address: p.address, ServerName: p.serverName}
	conn, err := net.DialTimeout("tcp", p.address, liveCheckTimeout)
	if err != nil {
		r.Status, r.ErrorCode = "UNREACHABLE", probeErrorCode(err, "TCP_CONNECT_FAILED")
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(liveCheckTimeout))
	// 只比对指纹，不校验信任链：本机地址与证书名称本来就对不上，原证书也可能是自签名的
	tc := tls.Client(conn, &tls.Config{ServerName: p.serverName, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		r.Status, r.ErrorCode = "UNREACHABLE", probeErrorCode(err, "TLS_HANDSHAKE_FAILED")
		return r
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		r.Status, r.ErrorCode = "UNREACHABLE", "NO_CERTIFICATE_PRESENT"
		return r
	}
	if sha256.Sum256(certs[0].Raw) == p.expected {
		r.Status = "VERIFIED"
		return r
	}
	expires := certs[0].NotAfter.UTC()
	r.Status = "MISMATCH"
	r.Subject = certs[0].Subject.CommonName
	r.Issuer = issuerName(certs[0])
	r.ExpiresAt = &expires
	return r
}

func probeErrorCode(err error, fallback string) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "TIMEOUT"
	}
	return fallback
}

func leafCertificate(content []byte) *x509.Certificate {
	for {
		var b *pem.Block
		b, content = pem.Decode(content)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

// 优先用确切名称；只有通配符时拼一个能匹配它的名称，让 Nginx 选中这个 server
func probeServerName(names []string) string {
	for _, n := range names {
		if !strings.ContainsAny(n, "*") && !strings.HasPrefix(n, ".") {
			return n
		}
	}
	for _, n := range names {
		switch {
		case strings.HasPrefix(n, "*."):
			return "lapsezero-check" + n[1:]
		case strings.HasPrefix(n, "."):
			return n[1:]
		}
	}
	return ""
}

// dialAddress 把 listen 的地址参数换成本机可连接的地址；监听全部地址时连回环地址
func dialAddress(listen string) string {
	if strings.HasPrefix(listen, "unix:") {
		return ""
	}
	host, port := "*", "80"
	switch {
	case isDigits(listen):
		port = listen
	case strings.HasPrefix(listen, "["):
		end := strings.Index(listen, "]")
		if end < 0 {
			return ""
		}
		host = listen[1:end]
		if rest, ok := strings.CutPrefix(listen[end+1:], ":"); ok {
			port = rest
		}
	default:
		h, p, ok := strings.Cut(listen, ":")
		host = h
		if ok {
			port = p
		}
	}
	switch host {
	case "*", "0.0.0.0", "":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func issuerName(cert *x509.Certificate) string {
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}
