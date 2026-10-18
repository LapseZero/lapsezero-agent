package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type npmCredential struct {
	Identity string `json:"identity"`
	Secret   string `json:"secret"`
}
type npmTask struct {
	ContainerName string `json:"containerName"`
	CertificateID int64  `json:"certificateId"`
	npmCredential
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"privateKey"`
	CACertificate string `json:"caCertificate"`
}
type npmSite struct {
	CertificateID int64        `json:"certificateId"`
	NiceName      string       `json:"niceName"`
	ServerNames   []string     `json:"serverNames"`
	Websites      []string     `json:"websites"`
	Certificate   *certSummary `json:"certificate"`
	Unsupported   bool         `json:"unsupported"`
}
type npmScan struct {
	ContainerName string    `json:"containerName"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	Sites         []npmSite `json:"sites"`
}
type npmHost struct {
	DomainNames []string `json:"domain_names"`
	Enabled     bool     `json:"enabled"`
}
type npmRecord struct {
	ID          int64    `json:"id"`
	Provider    string   `json:"provider"`
	NiceName    string   `json:"nice_name"`
	DomainNames []string `json:"domain_names"`
	Meta        struct {
		Certificate  string `json:"certificate"`
		Key          string `json:"certificate_key"`
		Intermediate string `json:"intermediate_certificate"`
	} `json:"meta"`
	ProxyHosts       []npmHost         `json:"proxy_hosts"`
	RedirectionHosts []npmHost         `json:"redirection_hosts"`
	DeadHosts        []npmHost         `json:"dead_hosts"`
	Streams          []json.RawMessage `json:"streams"`
}
type npmContainer struct {
	ID         string
	Name       string
	APIAddress string
	TLSAddress string
}
type npmClient struct {
	container npmContainer
	token     string
	http      *http.Client
}
type npmError struct {
	code    string
	message string
	status  int
}

func (e *npmError) Error() string { return e.message }

func dockerOutput(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).Output()
}

// 只接受官方镜像的运行中容器；容器名称在重建后保持稳定，执行时使用本次检查取得的 ID。
func npmContainers() ([]npmContainer, error) {
	if _, err := exec.LookPath("docker"); errors.Is(err, exec.ErrNotFound) {
		return nil, nil
	}
	out, err := dockerOutput("ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	if err != nil {
		return nil, err
	}
	var containers []npmContainer
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			continue
		}
		image := strings.TrimPrefix(fields[1], "docker.io/")
		if image != "jc21/nginx-proxy-manager" && !strings.HasPrefix(image, "jc21/nginx-proxy-manager:") && !strings.HasPrefix(image, "jc21/nginx-proxy-manager@") {
			continue
		}
		c, err := inspectNpmContainer(fields[0], fields[2])
		if err != nil {
			return nil, err
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func inspectNpmContainer(id, name string) (npmContainer, error) {
	out, err := dockerOutput("inspect", "--format", "{{json .NetworkSettings}}", id)
	if err != nil {
		return npmContainer{}, err
	}
	var settings struct {
		Ports map[string][]struct {
			HostIP   string
			HostPort string
		}
		Networks map[string]struct{ IPAddress string }
	}
	if err := json.Unmarshal(out, &settings); err != nil {
		return npmContainer{}, err
	}
	address := func(port string) string {
		for _, binding := range settings.Ports[port+"/tcp"] {
			host := binding.HostIP
			if host == "0.0.0.0" || host == "" {
				host = "127.0.0.1"
			}
			if host == "::" {
				host = "::1"
			}
			if binding.HostPort != "" {
				return net.JoinHostPort(host, binding.HostPort)
			}
		}
		// 未发布管理端口时，Linux 宿主机直接访问容器网络；host 网络连接回环地址。
		names := make([]string, 0, len(settings.Networks))
		for name := range settings.Networks {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if ip := settings.Networks[name].IPAddress; ip != "" {
				return net.JoinHostPort(ip, port)
			}
		}
		return net.JoinHostPort("127.0.0.1", port)
	}
	return npmContainer{ID: id, Name: name, APIAddress: address("81"), TLSAddress: address("443")}, nil
}

func newNpmClient(c npmContainer, credential npmCredential) (*npmClient, error) {
	client := &npmClient{container: c, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	var login struct {
		Token string `json:"token"`
	}
	if err := client.json(http.MethodPost, "/tokens", credential, &login); err != nil {
		return nil, err
	}
	if login.Token == "" {
		return nil, &npmError{"AUTH_FAILED", "NPM requires a password account without an interactive login challenge", 0}
	}
	client.token = login.Token
	// 全部关联名称必须可见，否则有限可见性的账号会漏掉共享证书的其他站点。
	var user struct {
		Roles       []string `json:"roles"`
		Permissions struct {
			Visibility   string `json:"visibility"`
			Certificates string `json:"certificates"`
		} `json:"permissions"`
	}
	if err := client.json(http.MethodGet, "/users/me?expand=permissions", nil, &user); err != nil {
		return nil, err
	}
	if !contains(user.Roles, "admin") && (user.Permissions.Visibility != "all" || user.Permissions.Certificates != "manage") {
		return nil, &npmError{"AUTH_FAILED", "NPM account needs all-host visibility and certificate management permission", 0}
	}
	return client, nil
}

func (c *npmClient) request(method, path, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequest(method, "http://"+c.container.APIAddress+"/api"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := "API_FAILED"
		if resp.StatusCode == 401 || resp.StatusCode == 403 || (path == "/tokens" && resp.StatusCode == 400) {
			code = "AUTH_FAILED"
		}
		if resp.StatusCode == 404 {
			code = "CERTIFICATE_NOT_FOUND"
		}
		// 不带回响应体：证书上传响应及上游报错可能包含私钥。
		return &npmError{code, fmt.Sprintf("NPM returned HTTP %d", resp.StatusCode), resp.StatusCode}
	}
	if out == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}
func (c *npmClient) json(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	return c.request(method, path, "application/json", reader, out)
}

const npmExpand = "?expand=proxy_hosts,redirection_hosts,dead_hosts,streams"

func (c *npmClient) record(id int64) (npmRecord, error) {
	var r npmRecord
	err := c.json(http.MethodGet, fmt.Sprintf("/nginx/certificates/%d%s", id, npmExpand), nil, &r)
	return r, err
}

func npmRecordNames(r npmRecord) ([]string, []string) {
	names := append([]string{}, r.DomainNames...)
	websites := []string{}
	if cert := leafCertificate([]byte(r.Meta.Certificate)); cert != nil {
		names = append(names, cert.DNSNames...)
	}
	for _, hosts := range [][]npmHost{r.ProxyHosts, r.RedirectionHosts, r.DeadHosts} {
		for _, host := range hosts {
			names = append(names, host.DomainNames...)
			websites = append(websites, host.DomainNames...)
		}
	}
	unique := func(values []string) []string {
		out := []string{}
		for _, value := range values {
			value = strings.ToLower(strings.TrimSuffix(value, "."))
			if !contains(out, value) {
				out = append(out, value)
			}
		}
		sort.Strings(out)
		return out
	}
	return unique(names), unique(websites)
}
func npmUnsupported(r npmRecord) bool {
	return r.Provider != "other" || leafCertificate([]byte(r.Meta.Certificate)) == nil || r.Meta.Key == "" || len(r.Streams) > 0
}
func npmFailure(err error) result {
	var upstream *npmError
	if errors.As(err, &upstream) {
		return result{Status: "FAILED", Error: "NPM_" + upstream.code, Message: upstream.message}
	}
	var network net.Error
	if errors.As(err, &network) {
		return result{Status: "FAILED", Error: "NPM_UNREACHABLE"}
	}
	return result{Status: "FAILED", Error: "INTERNAL", Message: err.Error()}
}
func scanNpm(credentials map[string]npmCredential) []npmScan {
	// 列不出容器时无法确认这台服务器用了 NPM，不显示 NPM 区域
	containers, err := npmContainers()
	if err != nil {
		return []npmScan{}
	}
	scans := []npmScan{}
	for _, container := range containers {
		scan := npmScan{ContainerName: container.Name, Status: "KEY_REQUIRED", Sites: []npmSite{}}
		if credential, ok := credentials[container.Name]; ok {
			c, err := newNpmClient(container, credential)
			if err == nil {
				var records []npmRecord
				err = c.json(http.MethodGet, "/nginx/certificates"+npmExpand, nil, &records)
				if err == nil {
					scan.Status = "OK"
					for _, r := range records {
						names, websites := npmRecordNames(r)
						scan.Sites = append(scan.Sites, npmSite{CertificateID: r.ID, NiceName: r.NiceName, ServerNames: names, Websites: websites, Certificate: certSummaryFromPEM([]byte(r.Meta.Certificate)), Unsupported: npmUnsupported(r)})
					}
				}
			}
			if err != nil {
				failure := npmFailure(err)
				scan.Status = "API_FAILED"
				if failure.Error == "NPM_AUTH_FAILED" {
					scan.Status = "KEY_INVALID"
				}
				if failure.Error == "NPM_UNREACHABLE" {
					scan.Status = "UNREACHABLE"
				}
			}
		}
		scans = append(scans, scan)
	}
	return scans
}

func (c *npmClient) upload(id int64, cert, key, chain string) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	// NPM 不接受空证书文件；记录原来没有独立中间链时，把完整链写进 certificate。
	for _, field := range [][2]string{{"certificate", cert}, {"certificate_key", key}, {"intermediate_certificate", chain}} {
		if field[0] == "intermediate_certificate" && field[1] == "" {
			continue
		}
		part, err := writer.CreateFormFile(field[0], field[0]+".pem")
		if err != nil {
			return err
		}
		if _, err = io.WriteString(part, field[1]); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return c.request(http.MethodPost, fmt.Sprintf("/nginx/certificates/%d/upload", id), writer.FormDataContentType(), &body, nil)
}
func (c *npmClient) checkConfig() error {
	if _, err := dockerOutput("exec", c.container.ID, "nginx", "-t"); err != nil {
		return &npmError{"API_FAILED", "NPM nginx configuration check failed", 0}
	}
	return nil
}
func (c *npmClient) reload() error {
	if err := c.checkConfig(); err != nil {
		return err
	}
	if _, err := dockerOutput("exec", c.container.ID, "nginx", "-s", "reload"); err != nil {
		return &npmError{"API_FAILED", "NPM nginx reload failed", 0}
	}
	return nil
}
func (c *npmClient) live(r npmRecord, leaf *x509.Certificate) *liveCheck {
	var probes []liveProbe
	for _, hosts := range [][]npmHost{r.ProxyHosts, r.RedirectionHosts, r.DeadHosts} {
		for _, host := range hosts {
			if host.Enabled {
				for _, name := range host.DomainNames {
					probes = append(probes, liveProbe{address: c.container.TLSAddress, serverName: probeServerName([]string{name}), expected: sha256.Sum256(leaf.Raw)})
				}
			}
		}
	}
	if len(probes) == 0 {
		return nil
	}
	return waitLive(probes)
}
func npmConnect(t npmTask) (*npmClient, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`).MatchString(t.ContainerName) {
		return nil, &npmError{"API_FAILED", "Invalid NPM container name", 0}
	}
	containers, err := npmContainers()
	if err != nil {
		return nil, &npmError{"UNREACHABLE", "Cannot inspect Docker containers", 0}
	}
	for _, container := range containers {
		if container.Name == t.ContainerName {
			return newNpmClient(container, t.npmCredential)
		}
	}
	return nil, &npmError{"UNREACHABLE", "NPM container is not running", 0}
}

// 只在本次部署内回滚，不写恢复记录：上传不会重载 Nginx，客户端中途退出时网站仍用内存中的旧证书，
// 重新部署会走到证书相同的分支完成重载和核查
func deployNpm(t npmTask) (result, error) {
	c, err := npmConnect(t)
	if err != nil {
		return npmFailure(err), nil
	}
	record, err := c.record(t.CertificateID)
	if err != nil {
		return npmFailure(err), nil
	}
	if npmUnsupported(record) {
		return result{Status: "FAILED", Error: "NPM_UNSUPPORTED_CERTIFICATE"}, nil
	}
	pair, err := tls.X509KeyPair([]byte(t.Certificate), []byte(t.PrivateKey))
	if err != nil {
		return result{}, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return result{}, err
	}
	names, _ := npmRecordNames(record)
	for _, name := range names {
		// 通配符必须原样保留，不能用一个具体子域名替代；普通域名交给标准库做单级通配符验证。
		covered := contains(leaf.DNSNames, name)
		if !covered && !strings.HasPrefix(name, "*.") {
			covered = leaf.VerifyHostname(name) == nil
		}
		if !covered {
			return result{Status: "FAILED", Error: "NPM_DOMAIN_NOT_COVERED"}, nil
		}
	}
	if record.Meta.Intermediate == "" {
		if t.CACertificate != "" {
			t.Certificate = strings.TrimSpace(t.Certificate) + "\n" + t.CACertificate
			t.CACertificate = ""
		}
	} else if t.CACertificate == "" {
		return result{Status: "FAILED", Error: "NPM_UNSUPPORTED_CERTIFICATE"}, nil
	}
	if strings.TrimSpace(record.Meta.Certificate) == strings.TrimSpace(t.Certificate) && strings.TrimSpace(record.Meta.Intermediate) == strings.TrimSpace(t.CACertificate) {
		if err = c.reload(); err != nil {
			return npmFailure(err), nil
		}
		return result{Status: "SUCCESS", LiveCheck: c.live(record, leaf)}, nil
	}
	// NPM 原有配置检查不通过时，换上的证书也无法加载，回滚同样会失败，所以先检查、不改动
	if err = c.checkConfig(); err != nil {
		return npmFailure(err), nil
	}
	err = c.upload(t.CertificateID, t.Certificate, t.PrivateKey, t.CACertificate)
	// NPM 先校验再写入，校验不通过（400）时记录和文件都没有改动，不需要回滚
	var rejected *npmError
	if errors.As(err, &rejected) && rejected.status == http.StatusBadRequest {
		return npmFailure(err), nil
	}
	if err == nil {
		var current npmRecord
		current, err = c.record(t.CertificateID)
		if err == nil && (strings.TrimSpace(current.Meta.Certificate) != strings.TrimSpace(t.Certificate) || strings.TrimSpace(current.Meta.Intermediate) != strings.TrimSpace(t.CACertificate)) {
			err = &npmError{"API_FAILED", "NPM certificate read-back did not match", 0}
		}
	}
	if err == nil {
		err = c.reload()
	}
	if err != nil {
		// 原证书已过期时 NPM 会拒绝上传，回滚失败；只上报，不影响客户端处理其他任务
		restoreErr := c.upload(t.CertificateID, record.Meta.Certificate, record.Meta.Key, record.Meta.Intermediate)
		if restoreErr == nil {
			restoreErr = c.reload()
		}
		if restoreErr != nil {
			return result{Status: "FAILED", Error: "NPM_ROLLBACK_FAILED"}, nil
		}
		return result{Status: "ROLLED_BACK", Error: "NPM_API_FAILED"}, nil
	}
	return result{Status: "SUCCESS", LiveCheck: c.live(record, leaf)}, nil
}
