package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// 替换被其他站点引用的文件会悄悄影响那些站点，两边都不能接管；完全相同的文件组合归并成一个站点
func TestApacheSitesRejectSharedFiles(t *testing.T) {
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	chain := file("chain.pem")
	// 硬链接的路径不同，写入时改的是同一个文件
	chainLink := filepath.Join(dir, "chain-link.pem")
	if err := os.Link(chain, chainLink); err != nil {
		t.Fatal(err)
	}
	aCert, aKey := file("a.crt"), file("a.key")
	bCert, bKey := file("b.crt"), file("b.key")
	cCert, cKey := file("c.crt"), file("c.key")
	link := filepath.Join(dir, "c-link.crt")
	if err := os.Symlink(cCert, link); err != nil {
		t.Fatal(err)
	}

	vhost := func(name, cert, key string, chains ...string) *apacheServer {
		return &apacheServer{name: name, bindings: []string{"*:443"}, ssl: "on", certs: []string{cert}, keys: []string{key}, chains: chains}
	}
	p := &apacheParser{
		listens: []string{"443"},
		vhosts: []*apacheServer{
			vhost("a.example.com", aCert, aKey, chain),
			vhost("b.example.com", bCert, bKey, chainLink),
			vhost("c.example.com", cCert, cKey),
			vhost("www.c.example.com", link, cKey),
		},
	}
	sites, rej := p.sites()
	if rej != nil {
		t.Fatal(rej)
	}
	if len(sites) != 3 {
		t.Fatalf("got %d sites, want 3", len(sites))
	}
	for i, want := range []string{chain, chainLink} {
		if s := sites[i]; s.Eligible || s.Reason != "SHARED_FILE" || s.SharedPath != want {
			t.Errorf("site %v: eligible=%v reason=%q shared=%q, want SHARED_FILE on %s", s.ServerNames, s.Eligible, s.Reason, s.SharedPath, want)
		}
	}
	if !sites[2].Eligible || !reflect.DeepEqual(sites[2].ServerNames, []string{"c.example.com", "www.c.example.com"}) {
		t.Errorf("merged site = %+v", sites[2])
	}
}

// 全局配置了两组证书时，虚拟主机只覆盖第一组，第二组仍然生效，也算这个站点用到的文件
func TestApacheSitesInheritRemainingCertificates(t *testing.T) {
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rsaCert, rsaKey, eccCert, eccKey := file("rsa.crt"), file("rsa.key"), file("ecc.crt"), file("ecc.key")
	aCert, aKey := file("a.crt"), file("a.key")
	p := &apacheParser{
		listens: []string{"443"},
		main:    apacheServer{ssl: "on", certs: []string{rsaCert, eccCert}, keys: []string{rsaKey, eccKey}},
		vhosts: []*apacheServer{
			{name: "a.example.com", bindings: []string{"*:443"}, certs: []string{aCert}, keys: []string{aKey}},
			{name: "b.example.com", bindings: []string{"*:443"}, certs: []string{eccCert}, keys: []string{eccKey}},
		},
	}
	sites, rej := p.sites()
	if rej != nil {
		t.Fatal(rej)
	}
	if sites[0].Eligible || sites[0].Reason != "MULTIPLE_CERTIFICATES" {
		t.Errorf("a: %+v, want MULTIPLE_CERTIFICATES", sites[0])
	}
	if sites[1].Eligible {
		t.Errorf("b: %+v, want rejected because a also serves its files", sites[1])
	}
}

// 读错一个反斜杠就会把证书写到另一个文件
func TestApacheFieldsEscapes(t *testing.T) {
	for in, want := range map[string][]string{
		`"a\cert.crt"`:  {`a\cert.crt`},
		`"a\\b" 'c\'d'`: {`a\b`, `c'd`},
		`a\\b "x y"`:    {`a\b`, `x y`},
		`"a\"b" c`:      {`a"b`, `c`},
	} {
		got, ok := apacheFields(in)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("apacheFields(%s) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
