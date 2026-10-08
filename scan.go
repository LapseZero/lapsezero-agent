package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const scanCommandTimeout = 30 * time.Second

// 不在 PATH 里的常见安装位置：源码编译、OpenResty、宝塔面板
var nginxFallbackPaths = []string{
	"/usr/local/nginx/sbin/nginx",
	"/usr/local/openresty/nginx/sbin/nginx",
	"/www/server/nginx/sbin/nginx",
}

// 与平台 agentScanResultSchema 一致。只上报路径和公开证书信息，不读取私钥内容
type scanResult struct {
	Status        string     `json:"status"`
	Error         string     `json:"error,omitempty"`
	ReloadCommand string     `json:"reloadCommand"`
	Sites         []scanSite `json:"sites"`
}

type scanSite struct {
	ServerNames []string     `json:"serverNames"`
	CertPath    string       `json:"certPath"`
	KeyPath     string       `json:"keyPath"`
	Certificate *certSummary `json:"certificate"`
	Renewal     *renewalInfo `json:"renewal"`
}

type certSummary struct {
	SubjectAltNames   []string  `json:"subjectAltNames"`
	Issuer            string    `json:"issuer"`
	NotAfter          time.Time `json:"notAfter"`
	FingerprintSha256 string    `json:"fingerprintSha256"`
}

// 证书已由其他工具自动续期时，接管后两边会互相覆盖，需要提醒用户停用原来的续期
type renewalInfo struct {
	Tool string `json:"tool"` // certbot | acme.sh
	Name string `json:"name"`
	Ecc  bool   `json:"ecc,omitempty"`
}

func scanNginx() scanResult {
	bin := findNginx()
	if bin == "" {
		return scanResult{Status: "FAILED", Error: "NGINX_NOT_FOUND"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-T").Output()
	if err != nil {
		return scanResult{Status: "FAILED", Error: "NGINX_CONFIG_FAILED"}
	}

	pairs := parseNginxDump(out)
	acme := loadAcmeShConfigs()
	sites := []scanSite{}
	for _, p := range pairs {
		sites = append(sites, scanSite{
			ServerNames: p.serverNames,
			CertPath:    p.certPath,
			KeyPath:     p.keyPath,
			Certificate: readCertSummary(p.certPath),
			Renewal:     detectRenewal(p.certPath, p.keyPath, acme),
		})
	}
	return scanResult{Status: "SUCCESS", ReloadCommand: reloadCommand(bin), Sites: sites}
}

func findNginx() string {
	if p, err := exec.LookPath("nginx"); err == nil {
		return p
	}
	for _, p := range nginxFallbackPaths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// 由 systemd 管理时用 systemctl reload，否则直接给运行中的 master 发信号
func reloadCommand(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), scanCommandTimeout)
	defer cancel()
	if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "nginx").Run() == nil {
		return "nginx -t && systemctl reload nginx"
	}
	return bin + " -t && " + bin + " -s reload"
}

type certPair struct {
	serverNames []string
	certPath    string
	keyPath     string
}

// parseNginxDump 解析 nginx -T 的输出，按证书和私钥路径归并 http 下的 server 块。
// 路径带变量（按 SNI 动态选证书）或 data: 内联的配置无法按文件部署，直接跳过。
func parseNginxDump(dump []byte) []certPair {
	// 相对路径以主配置文件所在目录为基准，nginx -T 的第一段就是主配置文件
	confPrefix := ""
	if _, rest, ok := bytes.Cut(dump, []byte("# configuration file ")); ok {
		line, _, _ := bytes.Cut(rest, []byte("\n"))
		confPrefix = filepath.Dir(strings.TrimSuffix(string(line), ":"))
	}
	resolve := func(p string) string {
		if !filepath.IsAbs(p) && confPrefix != "" {
			return filepath.Join(confPrefix, p)
		}
		return filepath.Clean(p)
	}

	type block struct {
		name        string
		certs, keys []string
		serverNames []string
		ssl         bool
	}
	var stack []*block
	var httpCerts, httpKeys []string
	var args []string
	byPaths := map[[2]string]*certPair{}
	var order [][2]string

	inHTTP := func() bool { return len(stack) >= 1 && stack[0].name == "http" }
	collect := func(b *block) {
		certs, keys := b.certs, b.keys
		// 只有启用了 TLS 的 server 才会用到 http 级别的证书
		if len(certs) == 0 && b.ssl {
			certs, keys = httpCerts, httpKeys
		}
		for i, c := range certs {
			if i >= len(keys) {
				break
			}
			if strings.Contains(c, "$") || strings.Contains(keys[i], "$") ||
				strings.HasPrefix(c, "data:") || strings.HasPrefix(keys[i], "data:") {
				continue
			}
			k := [2]string{resolve(c), resolve(keys[i])}
			p, ok := byPaths[k]
			if !ok {
				p = &certPair{certPath: k[0], keyPath: k[1]}
				byPaths[k] = p
				order = append(order, k)
			}
			for _, n := range b.serverNames {
				if !contains(p.serverNames, n) {
					p.serverNames = append(p.serverNames, n)
				}
			}
		}
	}

	for _, tok := range tokenizeNginx(dump) {
		switch tok {
		case "{":
			name := ""
			if len(args) > 0 {
				name = args[0]
			}
			stack = append(stack, &block{name: name})
			args = nil
		case "}":
			if len(stack) == 0 {
				continue
			}
			b := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if b.name == "server" && len(stack) == 1 && stack[0].name == "http" {
				collect(b)
			}
			if b.name == "http" {
				httpCerts, httpKeys = nil, nil
			}
			args = nil
		case ";":
			if len(args) >= 2 && inHTTP() {
				cur := stack[len(stack)-1]
				switch args[0] {
				case "ssl_certificate":
					if len(stack) == 1 {
						httpCerts = append(httpCerts, args[1])
					} else if cur.name == "server" {
						cur.certs = append(cur.certs, args[1])
					}
				case "ssl_certificate_key":
					if len(stack) == 1 {
						httpKeys = append(httpKeys, args[1])
					} else if cur.name == "server" {
						cur.keys = append(cur.keys, args[1])
					}
				case "listen":
					if cur.name == "server" && (contains(args[2:], "ssl") || contains(args[2:], "quic")) {
						cur.ssl = true
					}
				case "ssl":
					if cur.name == "server" && args[1] == "on" {
						cur.ssl = true
					}
				case "server_name":
					if cur.name == "server" {
						for _, n := range args[1:] {
							// 正则名称和 "_" 这类占位名无法对应到域名
							if strings.Contains(n, ".") && !strings.HasPrefix(n, "~") {
								cur.serverNames = append(cur.serverNames, strings.ToLower(n))
							}
						}
					}
				}
			}
			args = nil
		default:
			args = append(args, tok)
		}
	}

	pairs := make([]certPair, 0, len(order))
	for _, k := range order {
		pairs = append(pairs, *byPaths[k])
	}
	return pairs
}

// tokenizeNginx 按 nginx 配置语法切分：去掉注释，处理引号和转义，把 { } ; 作为独立记号
func tokenizeNginx(src []byte) []string {
	var tokens []string
	var cur strings.Builder
	inToken := false
	flush := func() {
		if inToken {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inToken = false
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '#' && !inToken:
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			quote := c
			inToken = true
			for i++; i < len(src) && src[i] != quote; i++ {
				if src[i] == '\\' && i+1 < len(src) {
					i++
				}
				cur.WriteByte(src[i])
			}
		case c == '{' || c == '}' || c == ';':
			flush()
			tokens = append(tokens, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '\\' && i+1 < len(src):
			i++
			cur.WriteByte(src[i])
			inToken = true
		default:
			cur.WriteByte(c)
			inToken = true
		}
	}
	flush()
	return tokens
}

// 只解析 CERTIFICATE 块；ssl_certificate 指向的文件可能同时含私钥，私钥块不读取也不上报
func readCertSummary(path string) *certSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(cert.Raw)
		names := cert.DNSNames
		if len(names) == 0 && cert.Subject.CommonName != "" {
			names = []string{cert.Subject.CommonName}
		}
		issuer := cert.Issuer.CommonName
		if len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
		return &certSummary{
			SubjectAltNames:   names,
			Issuer:            issuer,
			NotAfter:          cert.NotAfter.UTC(),
			FingerprintSha256: strings.ToUpper(hex.EncodeToString(sum[:])),
		}
	}
}

type acmeShConfig struct {
	domain string
	ecc    bool
	paths  []string
}

// acme.sh 用 --install-cert 把证书复制到任意路径，只能从它的域名配置里反查
func loadAcmeShConfigs() []acmeShConfig {
	var confs []acmeShConfig
	homes, _ := filepath.Glob("/home/*/.acme.sh")
	homes = append([]string{"/root/.acme.sh"}, homes...)
	for _, home := range homes {
		files, _ := filepath.Glob(filepath.Join(home, "*", "*.conf"))
		for _, f := range files {
			dir := filepath.Base(filepath.Dir(f))
			// 域名配置文件与所在目录同名（ECC 证书目录带 _ecc 后缀）
			if strings.TrimSuffix(dir, "_ecc")+".conf" != filepath.Base(f) {
				continue
			}
			c, err := parseAcmeShConf(f)
			if err != nil {
				continue
			}
			c.ecc = strings.HasSuffix(dir, "_ecc")
			confs = append(confs, c)
		}
	}
	return confs
}

func parseAcmeShConf(path string) (acmeShConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return acmeShConfig{}, err
	}
	defer f.Close()
	var c acmeShConfig
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `'"`)
		switch key {
		case "Le_Domain":
			c.domain = value
		case "Le_RealCertPath", "Le_RealFullChainPath", "Le_RealKeyPath":
			if value != "" {
				c.paths = append(c.paths, filepath.Clean(value))
			}
		}
	}
	if c.domain == "" {
		return c, errors.New("missing Le_Domain")
	}
	return c, sc.Err()
}

func detectRenewal(certPath, keyPath string, acme []acmeShConfig) *renewalInfo {
	for _, p := range []string{certPath, keyPath} {
		if rest, ok := strings.CutPrefix(p, "/etc/letsencrypt/live/"); ok {
			if name, _, ok := strings.Cut(rest, "/"); ok {
				return &renewalInfo{Tool: "certbot", Name: name}
			}
		}
	}
	for _, c := range acme {
		if contains(c.paths, certPath) || contains(c.paths, keyPath) {
			return &renewalInfo{Tool: "acme.sh", Name: c.domain, Ecc: c.ecc}
		}
	}
	for _, p := range []string{certPath, keyPath} {
		if i := strings.Index(p, "/.acme.sh/"); i >= 0 {
			dir := filepath.Base(filepath.Dir(p))
			return &renewalInfo{Tool: "acme.sh", Name: strings.TrimSuffix(dir, "_ecc"), Ecc: strings.HasSuffix(dir, "_ecc")}
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
