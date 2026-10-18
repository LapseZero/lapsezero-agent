package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// 共享证书的保护范围包含所有绑定（包括禁用网站），不能只检查当前启用的 Proxy Host。
func TestNpmRecordNamesIncludesEveryBinding(t *testing.T) {
	record := npmRecord{DomainNames: []string{"*.example.com"},
		ProxyHosts:       []npmHost{{DomainNames: []string{"A.example.com."}, Enabled: true}},
		RedirectionHosts: []npmHost{{DomainNames: []string{"redirect.example.com"}, Enabled: true}},
		DeadHosts:        []npmHost{{DomainNames: []string{"disabled.example.com"}, Enabled: false}},
	}
	names, websites := npmRecordNames(record)
	if !reflect.DeepEqual(names, []string{"*.example.com", "a.example.com", "disabled.example.com", "redirect.example.com"}) || !reflect.DeepEqual(websites, []string{"a.example.com", "disabled.example.com", "redirect.example.com"}) {
		t.Fatalf("names %v, websites %v", names, websites)
	}
}

// 局部可见性会漏掉其他用户的绑定，必须在任何部署读取/写入前拒绝。
func TestNpmRejectsInsufficientPermissions(t *testing.T) {
	for _, permissions := range []map[string]string{{"visibility": "user", "certificates": "manage"}, {"visibility": "all", "certificates": "view"}} {
		t.Run(permissions["visibility"]+permissions["certificates"], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/tokens":
					json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
				case "/api/users/me":
					json.NewEncoder(w).Encode(map[string]any{"roles": []string{}, "permissions": permissions})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			_, err := newNpmClient(npmContainer{APIAddress: strings.TrimPrefix(server.URL, "http://")}, npmCredential{})
			if err == nil || npmFailure(err).Error != "NPM_AUTH_FAILED" {
				t.Fatalf("expected permission rejection, got %v", err)
			}
		})
	}
}

// 上游返回体可能含证书私钥，不得进入任务日志或用户错误。
func TestNpmErrorsDoNotExposeResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"private-key-sentinel"}`))
	}))
	defer server.Close()
	c := npmClient{container: npmContainer{APIAddress: strings.TrimPrefix(server.URL, "http://")}, http: server.Client()}
	for _, path := range []string{"/tokens", "/nginx/certificates/1/upload"} {
		err := c.request(http.MethodPost, path, "application/json", nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
		got := npmFailure(err)
		expected := "NPM_API_FAILED"
		if path == "/tokens" {
			expected = "NPM_AUTH_FAILED"
		}
		if got.Error != expected || strings.Contains(got.Message, "private-key-sentinel") {
			t.Fatalf("unsafe or incorrect failure: %+v", got)
		}
	}
}

func TestNpmCoverageRejectionNeverWrites(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"a.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	for _, tc := range []struct {
		name  string
		names []string
		hosts []npmHost
	}{
		{"original wildcard", []string{"*.example.com"}, nil},
		{"another shared host", []string{"a.example.com"}, []npmHost{{DomainNames: []string{"b.example.com"}, Enabled: false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := npmRecord{ID: 1, Provider: "other", DomainNames: tc.names, ProxyHosts: tc.hosts}
			record.Meta.Certificate = certPEM
			record.Meta.Key = keyPEM
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/tokens":
					json.NewEncoder(w).Encode(map[string]string{"token": "test"})
				case "/api/users/me":
					json.NewEncoder(w).Encode(map[string]any{"roles": []string{"admin"}})
				case "/api/nginx/certificates/1":
					json.NewEncoder(w).Encode(record)
				default:
					writes++
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			// Docker discovery points to the isolated HTTP fixture; any exec would fail the test.
			script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\nps) echo 'abc\tjc21/nginx-proxy-manager:2.16.0\tnpm-test';;\ninspect) echo '{\"Ports\":{\"81/tcp\":[{\"HostIP\":\"%s\",\"HostPort\":\"%s\"}]}}';;\n*) exit 1;;\nesac\n", host, port)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			got, err := deployNpm(npmTask{ContainerName: "npm-test", CertificateID: 1, Certificate: certPEM, PrivateKey: keyPEM})
			if err != nil || got.Error != "NPM_DOMAIN_NOT_COVERED" || writes != 0 {
				t.Fatalf("result %+v, error %v, writes %d", got, err, writes)
			}
		})
	}
}
