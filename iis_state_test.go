package main

import (
	"errors"
	"net"
	"testing"
)

func TestIISRecoveryDecision(t *testing.T) {
	store, ctlID, ctlStore := "MY", "client-ca", "CA"
	old := iisSnapshot{SiteID: 1, BindingInformation: "*:443:example.com", SSLFlags: 5, Record: iisRecord{Hostname: "example.com", Hash: []byte{1, 2}, Store: &store, AppID: [16]byte{9}, CheckMode: 65543, Freshness: 123, Timeout: 2345, CTLID: &ctlID, CTLStore: &ctlStore, DefaultFlags: 1267}}
	old.Record.Address[0] = 2
	j := journal{AttemptID: "attempt", Phase: "prepared", Snapshot: &old, NewHash: []byte{3, 4}, NewStore: &store}
	next := iisNewSnapshot(j)
	for _, tc := range []struct {
		name          string
		current       *iisSnapshot
		class, action string
	}{
		{"old", &old, "OLD", "FAIL_OLD"},
		{"this new", &next, "THIS_NEW", "ROLLBACK"},
		{"binding missing", nil, "THIRD", "FAIL_THIRD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyIIS(j, tc.current); got != tc.class {
				t.Fatalf("class=%s want %s", got, tc.class)
			}
			if got := iisRecoveryAction(j, tc.current); got != tc.action {
				t.Fatalf("action=%s want %s", got, tc.action)
			}
		})
	}
	// 证书相同也不能覆盖管理员对任何其他基础字段或选定绑定的改动。
	mutations := map[string]func(*iisSnapshot){
		"third certificate": func(s *iisSnapshot) { s.Record.Hash = []byte{5} },
		"store":             func(s *iisSnapshot) { v := "WebHosting"; s.Record.Store = &v },
		"null store":        func(s *iisSnapshot) { s.Record.Store = nil },
		"app id":            func(s *iisSnapshot) { s.Record.AppID[1]++ },
		"check mode":        func(s *iisSnapshot) { s.Record.CheckMode++ },
		"freshness":         func(s *iisSnapshot) { s.Record.Freshness++ },
		"timeout":           func(s *iisSnapshot) { s.Record.Timeout++ },
		"ctl id":            func(s *iisSnapshot) { s.Record.CTLID = nil },
		"ctl store":         func(s *iisSnapshot) { s.Record.CTLStore = nil },
		"default flags":     func(s *iisSnapshot) { s.Record.DefaultFlags ^= 1 << 31 },
		"address":           func(s *iisSnapshot) { s.Record.Address[3]++ },
		"hostname":          func(s *iisSnapshot) { s.Record.Hostname = "other.example.com" },
		"site id":           func(s *iisSnapshot) { s.SiteID++ },
		"binding":           func(s *iisSnapshot) { s.BindingInformation = "127.0.0.1:443:example.com" },
		"ssl flags":         func(s *iisSnapshot) { s.SSLFlags ^= 1 << 6 },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			s := next
			change(&s)
			if classifyIIS(j, &s) != "THIRD" || iisRecoveryAction(j, &s) != "FAIL_THIRD" {
				t.Fatal("external state must not be overwritten")
			}
		})
	}
	for _, status := range []string{"SUCCESS", "FAILED", "ROLLED_BACK"} {
		finished := journal{Phase: "finished", Result: &result{Status: status}}
		if got := iisRecoveryAction(finished, nil); got != "REPORT" {
			t.Fatalf("finished %s must only report, got %s", status, got)
		}
	}
	// 默认 store 的 null 与显式 My 不混淆，写入和回滚保留原值。
	j.Snapshot = &iisSnapshot{Record: iisRecord{Hash: []byte{1}}}
	j.NewStore = nil
	n := iisNewSnapshot(j)
	if n.Record.Store != nil || classifyIIS(j, &n) != "THIS_NEW" {
		t.Fatal("null store was not preserved")
	}
}

func TestIISOwnership(t *testing.T) {
	binding := func(site uint64, s string) iisBinding {
		_, host, port, err := parseIISBinding(s)
		if err != nil {
			t.Fatal(err)
		}
		return iisBinding{SiteID: site, BindingInformation: s, Hostname: host, Port: port, SSLFlags: 5}
	}
	b := binding(1, "*:443:Example.COM")
	specific := binding(1, "192.0.2.1:443:example.com")
	ipv6 := binding(1, "[::1]:443:example.com")
	for _, tc := range []struct {
		name     string
		selected iisBinding
		all      []iisBinding
		ips      []iisIPMapping
		want     string
	}{
		{"exclusive", b, []iisBinding{b}, nil, ""},
		{"cross site", b, []iisBinding{b, binding(2, "*:443:example.com")}, nil, "SHARED_MAPPING"},
		{"cross IP", b, []iisBinding{b, binding(1, "192.0.2.1:443:example.com")}, nil, "SHARED_MAPPING"},
		{"other port", b, []iisBinding{b, binding(2, "*:4443:example.com")}, nil, ""},
		{"exact IPv4 shadows wildcard", b, []iisBinding{b}, []iisIPMapping{{net.ParseIP("127.0.0.1"), 443}}, "IP_SHADOWED"},
		{"exact IPv6 shadows wildcard", b, []iisBinding{b}, []iisIPMapping{{net.ParseIP("::1"), 443}}, "IP_SHADOWED"},
		{"exact selected IP", specific, []iisBinding{specific}, []iisIPMapping{{net.ParseIP("192.0.2.1"), 443}}, "IP_SHADOWED"},
		{"exact selected IPv6", ipv6, []iisBinding{ipv6}, []iisIPMapping{{net.ParseIP("::1"), 443}}, "IP_SHADOWED"},
		{"unrelated exact IP", specific, []iisBinding{specific}, []iisIPMapping{{net.ParseIP("192.0.2.2"), 443}}, ""},
		{"wildcard fallback", b, []iisBinding{b}, []iisIPMapping{{net.ParseIP("0.0.0.0"), 443}, {net.ParseIP("::"), 443}}, ""},
		{"other IP port", b, []iisBinding{b}, []iisIPMapping{{net.ParseIP("127.0.0.1"), 4443}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := iisOwnership(tc.selected, tc.all, tc.ips); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	b.SSLFlags = 3
	if iisOwnership(b, []iisBinding{b}, nil) != "CCS" {
		t.Fatal("CCS accepted")
	}
	b.SSLFlags = 0
	if iisOwnership(b, []iisBinding{b}, nil) != "NOT_SNI" {
		t.Fatal("non-SNI accepted")
	}
}

func TestIISOwnershipIncludesStoppedSitesAndRejectsDefaultBindings(t *testing.T) {
	data := []byte(`<configuration><system.applicationHost><sites>
 <site id="1" name="running"><bindings><binding protocol="https" bindingInformation="*:443:example.com" sslFlags="5"/></bindings></site>
 <site id="2" name="stopped" serverAutoStart="false"><bindings><binding protocol="https" bindingInformation="192.0.2.1:443:EXAMPLE.COM" sslFlags="1"/></bindings></site>
 </sites></system.applicationHost></configuration>`)
	bindings, err := parseIISSites(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 || iisOwnership(bindings[0], bindings, nil) != "SHARED_MAPPING" {
		t.Fatal("stopped site was not counted")
	}
	_, err = parseIISSites([]byte(`<configuration><system.applicationHost><sites><siteDefaults><bindings><binding protocol="https" bindingInformation="*:443:example.com" sslFlags="1"/></bindings></siteDefaults></sites></system.applicationHost></configuration>`))
	if !errors.Is(err, errIISConfigUnsupported) {
		t.Fatalf("default bindings must reject the whole scan, got %v", err)
	}
}
