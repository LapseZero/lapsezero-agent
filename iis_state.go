package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
)

type iisTask struct {
	SiteID             uint64 `json:"siteId"`
	BindingInformation string `json:"bindingInformation"`
	PFXBase64          string `json:"pfxBase64"`
	PFXPassword        string `json:"pfxPassword"`
	FingerprintSha256  string `json:"fingerprintSha256"`
}

type iisResult struct {
	ThumbprintSha1    string `json:"thumbprintSha1"`
	FingerprintSha256 string `json:"fingerprintSha256"`
	CertificateStore  string `json:"certificateStore"`
	Changed           bool   `json:"changed"`
}

type iisBinding struct {
	SiteID             uint64       `json:"siteId"`
	SiteName           string       `json:"siteName"`
	BindingInformation string       `json:"bindingInformation"`
	Hostname           string       `json:"hostname"`
	Port               uint16       `json:"port"`
	SSLFlags           uint32       `json:"sslFlags"`
	CertificateStore   *string      `json:"certificateStore"`
	Certificate        *certSummary `json:"certificate"`
	Eligible           bool         `json:"eligible"`
	Reason             *string      `json:"reason"`
}

type iisScan struct {
	Status   string       `json:"status"`
	Error    string       `json:"error,omitempty"`
	Message  string       `json:"message,omitempty"`
	Bindings []iisBinding `json:"bindings"`
}

// 指针字段保存值及 null；不能保存 HTTP API 返回缓冲区中的地址。
type iisRecord struct {
	Address      [128]byte
	Hostname     string
	Hash         []byte
	Store        *string
	AppID        [16]byte
	CheckMode    uint32
	Freshness    uint32
	Timeout      uint32
	CTLID        *string
	CTLStore     *string
	DefaultFlags uint32
}

type iisSnapshot struct {
	Record             iisRecord
	SiteID             uint64
	BindingInformation string
	SSLFlags           uint32
}

func iisNewSnapshot(j journal) iisSnapshot {
	s := *j.Snapshot
	s.Record.Hash = j.NewHash
	// 首版沿用当前存储，保留原始大小写和 null，避免回读误判第三态。
	s.Record.Store = j.NewStore
	return s
}

func classifyIIS(j journal, current *iisSnapshot) string {
	if current != nil && reflect.DeepEqual(*current, *j.Snapshot) {
		return "OLD"
	}
	if current != nil && reflect.DeepEqual(*current, iisNewSnapshot(j)) {
		return "THIS_NEW"
	}
	return "THIRD"
}

func iisRecoveryAction(j journal, current *iisSnapshot) string {
	if j.Phase == "finished" {
		return "REPORT"
	}
	switch classifyIIS(j, current) {
	case "OLD":
		return "FAIL_OLD"
	case "THIS_NEW":
		return "ROLLBACK"
	default:
		return "FAIL_THIRD"
	}
}

func parseIISBinding(s string) (ip, hostname string, port uint16, err error) {
	last := strings.LastIndexByte(s, ':')
	if last < 0 {
		return "", "", 0, fmt.Errorf("invalid IIS binding: %q", s)
	}
	prev := strings.LastIndexByte(s[:last], ':')
	if prev < 0 {
		return "", "", 0, fmt.Errorf("invalid IIS binding: %q", s)
	}
	n, e := strconv.ParseUint(s[prev+1:last], 10, 16)
	if e != nil || n == 0 {
		return "", "", 0, fmt.Errorf("invalid IIS binding port: %q", s)
	}
	ip = strings.Trim(s[:prev], "[]")
	if ip != "*" && ip != "" && net.ParseIP(ip) == nil {
		return "", "", 0, fmt.Errorf("invalid IIS binding IP: %q", s)
	}
	return ip, strings.ToLower(strings.TrimSuffix(s[last+1:], ".")), uint16(n), nil
}

type iisIPMapping struct {
	IP   net.IP
	Port uint16
}

// HTTP.sys 的 SNI key 不含 siteId 或绑定 IP；停止站点同样占用该 key。
func iisOwnership(selected iisBinding, all []iisBinding, exact []iisIPMapping) string {
	if selected.SSLFlags&2 != 0 {
		return "CCS"
	}
	if selected.SSLFlags&1 == 0 || selected.Hostname == "" || strings.ContainsAny(selected.Hostname, "*? \t\r\n") {
		return "NOT_SNI"
	}
	count := 0
	for _, b := range all {
		if b.Hostname == selected.Hostname && b.Port == selected.Port {
			count++
		}
	}
	if count != 1 {
		return "SHARED_MAPPING"
	}
	ip, _, _, err := parseIISBinding(selected.BindingInformation)
	if err != nil {
		return "OWNER_UNKNOWN"
	}
	selectedIP := net.ParseIP(ip)
	for _, m := range exact {
		if m.Port == selected.Port && !m.IP.IsUnspecified() && (selectedIP == nil || selectedIP.IsUnspecified() || selectedIP.Equal(m.IP)) {
			return "IP_SHADOWED"
		}
	}
	return ""
}

var errIISConfigUnsupported = errors.New("IIS_CONFIG_UNSUPPORTED")

func parseIISSites(data []byte) ([]iisBinding, error) {
	var config struct {
		Sites struct {
			Defaults struct {
				Children []struct{ XMLName xml.Name } `xml:",any"`
			} `xml:"siteDefaults>bindings"`
			Sites []struct {
				ID       uint64 `xml:"id,attr"`
				Name     string `xml:"name,attr"`
				Bindings []struct {
					Protocol    string `xml:"protocol,attr"`
					Information string `xml:"bindingInformation,attr"`
					Flags       uint32 `xml:"sslFlags,attr"`
				} `xml:"bindings>binding"`
			} `xml:"site"`
		} `xml:"system.applicationHost>sites"`
	}
	if err := xml.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &config); err != nil {
		return nil, err
	}
	if len(config.Sites.Defaults.Children) != 0 {
		return nil, errIISConfigUnsupported
	}
	out := []iisBinding{}
	for _, s := range config.Sites.Sites {
		for _, b := range s.Bindings {
			if b.Protocol != "https" {
				continue
			}
			_, host, port, err := parseIISBinding(b.Information)
			if err != nil {
				return nil, err
			}
			out = append(out, iisBinding{SiteID: s.ID, SiteName: s.Name, BindingInformation: b.Information, Hostname: host, Port: port, SSLFlags: b.Flags})
		}
	}
	return out, nil
}

func iisStoreName(s *string) string {
	if s == nil || strings.EqualFold(*s, "My") {
		return "My"
	}
	if strings.EqualFold(*s, "WebHosting") {
		return "WebHosting"
	}
	return *s
}
