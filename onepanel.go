package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 1Panel 的 OpenResty 跑在容器里，网站证书以 1Panel 数据库为准：直接改证书文件，
// 用户下次在面板里保存网站设置时会被改回旧证书。所以通过本机的 1Panel API 更新证书记录，
// 由 1Panel 同步到使用它的网站并重载。API Key 由用户在 1Panel 创建，白名单填 127.0.0.1。

// 与平台 agentScanResultSchema 中的 onePanel 一致
type onePanelScan struct {
	Status  string         `json:"status"` // OK | KEY_REQUIRED | KEY_INVALID | UNREACHABLE | UNSUPPORTED_VERSION | API_FAILED
	Message string         `json:"message,omitempty"`
	Sites   []onePanelSite `json:"sites,omitempty"`
}

// 一条证书记录可以被多个网站使用，更新记录就同时更新这些网站，所以按证书记录上报
type onePanelSite struct {
	SslID       int64        `json:"sslId"`
	Websites    []string     `json:"websites"`
	ServerNames []string     `json:"serverNames"`
	Certificate *certSummary `json:"certificate"`
	AutoRenew   bool         `json:"autoRenew"`
}

type onePanelTask struct {
	SslID       int64  `json:"sslId"`
	APIKey      string `json:"apiKey"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

var (
	errOnePanelAuth        = errors.New("1Panel rejected the API key")
	errOnePanelUnsupported = errors.New("unexpected response from 1Panel")
)

// onePanelAPIError 是 1Panel 返回的业务错误
type onePanelAPIError struct {
	Code    int
	Message string
}

func (e *onePanelAPIError) Error() string {
	return fmt.Sprintf("1Panel: %s (code %d)", e.Message, e.Code)
}

type onePanelClient struct {
	base   string
	prefix string // 接口路径前缀，v2 是 /api/v2，v1 是 /api/v1
	key    string
	http   *http.Client
}

// 1Panel 的进程名：v2 是 1panel-core，v1 是 1panel
var onePanelProcesses = []string{"1panel-core", "1panel"}

// onePanelAddress 找到本机 1Panel 面板监听的地址；没有运行 1Panel 时返回空。
// 面板端口可以在 1Panel 里随时修改，所以从进程的监听套接字找，不读安装时的配置
func onePanelAddress() string {
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range pids {
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil || !contains(onePanelProcesses, strings.TrimSpace(string(comm))) {
			continue
		}
		inodes := map[string]bool{}
		fds, _ := filepath.Glob(filepath.Join(dir, "fd", "*"))
		for _, fd := range fds {
			if link, err := os.Readlink(fd); err == nil && strings.HasPrefix(link, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
		for _, table := range []string{"tcp", "tcp6"} {
			if addr := listenAddress(filepath.Join(dir, "net", table), inodes); addr != "" {
				return addr
			}
		}
	}
	return ""
}

// 解析 /proc/<pid>/net/tcp：找属于该进程、处于监听状态（0A）的套接字
func listenAddress(path string, inodes map[string]bool) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" || !inodes[f[9]] {
			continue
		}
		hexIP, hexPort, ok := strings.Cut(f[1], ":")
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if !ok || err != nil {
			continue
		}
		host := "127.0.0.1"
		// 只监听某个 IPv4 地址时连它；监听全部地址时连回环地址
		if len(hexIP) == 8 && strings.Trim(hexIP, "0") != "" {
			b, err := hex.DecodeString(hexIP)
			if err != nil {
				continue
			}
			host = net.IPv4(b[3], b[2], b[1], b[0]).String()
		} else if len(hexIP) == 32 && strings.Trim(hexIP, "0") != "" {
			continue
		}
		return net.JoinHostPort(host, strconv.FormatUint(port, 10))
	}
	return ""
}

func newOnePanelClient(addr, key string) *onePanelClient {
	// 面板开启了 HTTPS 时用的多是自签名证书；连接的是本机地址，不校验证书
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	scheme := "http"
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
		conn.Close()
		scheme = "https"
	}
	return &onePanelClient{
		base:   scheme + "://" + addr,
		prefix: "/api/v2",
		key:    key,
		http:   &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

// v1 和 v2 的鉴权方式和用到的接口相同，只是路径前缀不同：先按 v2 调用，
// 返回的不是 JSON（v1 对不认识的路径返回 HTML 页面）时改用 v1，之后都按 v1 调用
func (c *onePanelClient) call(method, path string, body, out any) error {
	err := c.do(method, path, body, out)
	if errors.Is(err, errOnePanelUnsupported) && c.prefix == "/api/v2" {
		c.prefix = "/api/v1"
		err = c.do(method, path, body, out)
		if errors.Is(err, errOnePanelUnsupported) {
			c.prefix = "/api/v2"
		}
	}
	return err
}

func (c *onePanelClient) do(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, c.base+c.prefix+path, reader)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := md5.Sum([]byte("1panel" + c.key + ts))
	req.Header.Set("1Panel-Token", hex.EncodeToString(sum[:]))
	req.Header.Set("1Panel-Timestamp", ts)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errOnePanelUnsupported
	}
	switch envelope.Code {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errOnePanelAuth
	default:
		return &onePanelAPIError{Code: envelope.Code, Message: envelope.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Data, out)
}

type onePanelWebsite struct {
	ID            int64  `json:"id"`
	PrimaryDomain string `json:"primaryDomain"`
	WebSiteSSLID  int64  `json:"webSiteSSLId"`
	Domains       []struct {
		Domain string `json:"domain"`
	} `json:"domains"`
}

// httpsWebsites 返回启用了 HTTPS 的网站详情
func (c *onePanelClient) httpsWebsites() ([]onePanelWebsite, error) {
	var sites []onePanelWebsite
	for page := 1; ; page++ {
		var res struct {
			Total int `json:"total"`
			Items []struct {
				ID       int64  `json:"id"`
				Protocol string `json:"protocol"`
			} `json:"items"`
		}
		body := map[string]any{"page": page, "pageSize": 100, "orderBy": "created_at", "order": "null", "websiteGroupId": 0, "name": "", "type": ""}
		if err := c.call(http.MethodPost, "/websites/search", body, &res); err != nil {
			return nil, err
		}
		for _, item := range res.Items {
			if item.Protocol != "HTTPS" {
				continue
			}
			var site onePanelWebsite
			if err := c.call(http.MethodGet, fmt.Sprintf("/websites/%d", item.ID), nil, &site); err != nil {
				return nil, err
			}
			if site.WebSiteSSLID > 0 {
				sites = append(sites, site)
			}
		}
		if len(res.Items) < 100 || page*100 >= res.Total {
			return sites, nil
		}
	}
}

func scanOnePanel(addr string, key *string) *onePanelScan {
	if key == nil || *key == "" {
		return &onePanelScan{Status: "KEY_REQUIRED"}
	}
	c := newOnePanelClient(addr, *key)
	websites, err := c.httpsWebsites()
	if err != nil {
		return onePanelScanError(err)
	}
	var sites []onePanelSite
	index := map[int64]int{}
	for _, w := range websites {
		i, ok := index[w.WebSiteSSLID]
		if !ok {
			// 网站详情里不带证书内容，要单独查证书记录；响应里的私钥不读取
			var record struct {
				Pem       string `json:"pem"`
				AutoRenew bool   `json:"autoRenew"`
			}
			if err := c.call(http.MethodGet, fmt.Sprintf("/websites/ssl/%d", w.WebSiteSSLID), nil, &record); err != nil {
				return onePanelScanError(err)
			}
			i = len(sites)
			index[w.WebSiteSSLID] = i
			sites = append(sites, onePanelSite{
				SslID:       w.WebSiteSSLID,
				Websites:    []string{},
				ServerNames: []string{},
				Certificate: certSummaryFromPEM([]byte(record.Pem)),
				AutoRenew:   record.AutoRenew,
			})
		}
		s := &sites[i]
		s.Websites = append(s.Websites, w.PrimaryDomain)
		for _, d := range w.Domains {
			if !contains(s.ServerNames, d.Domain) {
				s.ServerNames = append(s.ServerNames, d.Domain)
			}
		}
	}
	if sites == nil {
		sites = []onePanelSite{}
	}
	return &onePanelScan{Status: "OK", Sites: sites}
}

func onePanelScanError(err error) *onePanelScan {
	var apiErr *onePanelAPIError
	switch {
	case errors.Is(err, errOnePanelAuth):
		return &onePanelScan{Status: "KEY_INVALID"}
	case errors.Is(err, errOnePanelUnsupported):
		return &onePanelScan{Status: "UNSUPPORTED_VERSION"}
	case errors.As(err, &apiErr):
		return &onePanelScan{Status: "API_FAILED", Message: apiErr.Message}
	default:
		return &onePanelScan{Status: "UNREACHABLE", Message: err.Error()}
	}
}

// deployOnePanel 用新证书覆盖 1Panel 里的这条证书记录，1Panel 会把它同步到使用这条记录的网站并重载。
// 重载失败时 1Panel 不会恢复：v2 的记录、v1 的证书文件已经是新证书，所以失败后要把原来的证书写回去
func deployOnePanel(t onePanelTask) result {
	addr := onePanelAddress()
	if addr == "" {
		return result{Status: "FAILED", Error: "ONEPANEL_UNREACHABLE", Message: "1Panel is not running on this server"}
	}
	c := newOnePanelClient(addr, t.APIKey)
	var record struct {
		Pem         string `json:"pem"`
		PrivateKey  string `json:"privateKey"`
		Description string `json:"description"`
	}
	if err := c.call(http.MethodGet, fmt.Sprintf("/websites/ssl/%d", t.SslID), nil, &record); err != nil {
		var apiErr *onePanelAPIError
		if errors.As(err, &apiErr) && strings.Contains(apiErr.Message, "record not found") {
			return result{Status: "FAILED", Error: "ONEPANEL_SSL_NOT_FOUND"}
		}
		return onePanelDeployError(err)
	}
	upload := func(cert, key string) error {
		return c.call(http.MethodPost, "/websites/ssl/upload", map[string]any{
			"type":        "paste",
			"sslID":       t.SslID,
			"certificate": cert,
			"privateKey":  key,
			// 不传会清空用户写的备注
			"description": record.Description,
		}, nil)
	}
	if err := upload(t.Certificate, t.PrivateKey); err != nil {
		var apiErr *onePanelAPIError
		if !errors.As(err, &apiErr) {
			return onePanelDeployError(err)
		}
		if restoreErr := upload(record.Pem, record.PrivateKey); restoreErr != nil {
			return result{Status: "FAILED", Error: "ONEPANEL_ROLLBACK_FAILED", Message: apiErr.Message}
		}
		return result{Status: "ROLLED_BACK", Error: "ONEPANEL_API_FAILED", Message: apiErr.Message}
	}
	r := result{Status: "SUCCESS"}
	r.LiveCheck = checkOnePanelLive(c, t)
	return r
}

func onePanelDeployError(err error) result {
	var apiErr *onePanelAPIError
	switch {
	case errors.Is(err, errOnePanelAuth):
		return result{Status: "FAILED", Error: "ONEPANEL_AUTH_FAILED"}
	case errors.As(err, &apiErr):
		return result{Status: "FAILED", Error: "ONEPANEL_API_FAILED", Message: apiErr.Message}
	case errors.Is(err, errOnePanelUnsupported):
		return result{Status: "FAILED", Error: "ONEPANEL_API_FAILED", Message: err.Error()}
	default:
		return result{Status: "FAILED", Error: "ONEPANEL_UNREACHABLE", Message: err.Error()}
	}
}

// checkOnePanelLive 在本机连接使用这条证书记录的网站，确认 OpenResty 已换上新证书。
// 查不到网站信息时返回 nil，表示无从检查，不影响部署结果
func checkOnePanelLive(c *onePanelClient, t onePanelTask) *liveCheck {
	leaf := leafCertificate([]byte(t.Certificate))
	if leaf == nil {
		return nil
	}
	websites, err := c.httpsWebsites()
	if err != nil {
		return nil
	}
	var probes []liveProbe
	v1Port := ""
	for _, w := range websites {
		if w.WebSiteSSLID != t.SslID {
			continue
		}
		var https struct {
			HTTPSPort string `json:"httpsPort"`
		}
		if err := c.call(http.MethodGet, fmt.Sprintf("/websites/%d/https", w.ID), nil, &https); err != nil {
			return nil
		}
		port := https.HTTPSPort
		// v1 的网站 HTTPS 配置里没有端口，网站都监听 OpenResty 安装时设置的 HTTPS 端口
		if port == "" {
			if v1Port == "" {
				if v1Port = c.openRestyHTTPSPort(); v1Port == "" {
					return nil
				}
			}
			port = v1Port
		}
		names := []string{w.PrimaryDomain}
		for _, d := range w.Domains {
			names = append(names, d.Domain)
		}
		probes = append(probes, liveProbe{address: net.JoinHostPort("127.0.0.1", port), serverName: probeServerName(names), expected: sha256.Sum256(leaf.Raw)})
	}
	if len(probes) == 0 {
		return nil
	}
	return waitLive(probes)
}

func (c *onePanelClient) openRestyHTTPSPort() string {
	var res struct {
		Items []struct {
			AppKey    string `json:"appKey"`
			HTTPSPort int    `json:"httpsPort"`
		} `json:"items"`
	}
	if err := c.call(http.MethodPost, "/apps/installed/search", map[string]any{"page": 1, "pageSize": 100, "type": "website"}, &res); err != nil {
		return ""
	}
	for _, item := range res.Items {
		if item.AppKey == "openresty" && item.HTTPSPort > 0 {
			return strconv.Itoa(item.HTTPSPort)
		}
	}
	return ""
}
