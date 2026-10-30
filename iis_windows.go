package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

var errIISSharedConfig = errors.New("SHARED_CONFIG")

func supportedIISOS() bool {
	v := windows.RtlGetVersion()
	if runtime.GOARCH != "amd64" || v.MajorVersion != 10 || v.ProductType == 1 {
		return false
	}
	// 只放行实机验收过的版本：Server 2016、2019、2022、2025
	switch v.BuildNumber {
	case 14393, 17763, 20348, 26100:
		return true
	}
	return false
}

func readIISBindings() ([]iisBinding, error) {
	dir := filepath.Join(os.Getenv("windir"), "System32", "inetsrv", "config")
	raw, err := os.ReadFile(filepath.Join(dir, "redirection.config"))
	if err != nil {
		return nil, err
	}
	var redirect struct {
		Redirection struct {
			Enabled bool `xml:"enabled,attr"`
		} `xml:"configurationRedirection"`
	}
	if err := xml.Unmarshal(raw, &redirect); err != nil {
		return nil, err
	}
	if redirect.Redirection.Enabled {
		return nil, errIISSharedConfig
	}
	raw, err = os.ReadFile(filepath.Join(dir, "applicationHost.config"))
	if err != nil {
		return nil, err
	}
	return parseIISSites(raw)
}

func (a *agent) scan(req scanRequest) {
	r := iisScan{Status: "OK", Bindings: []iisBinding{}}
	bindings, err := readIISBindings()
	var mappings []iisIPMapping
	if err == nil && supportedIISOS() {
		mappings, err = readIPMappings()
	}
	if err != nil {
		r.Status, r.Error, r.Message = "ERROR", "IIS_READ_FAILED", failureMessage(err)
		switch {
		case errors.Is(err, os.ErrNotExist):
			r.Error = "IIS_NOT_FOUND"
		case errors.Is(err, errIISSharedConfig):
			r.Error = "SHARED_CONFIG"
		case errors.Is(err, errIISConfigUnsupported):
			r.Error = "IIS_CONFIG_UNSUPPORTED"
		}
	} else {
		for _, b := range bindings {
			reason := iisOwnership(b, bindings, mappings)
			if !supportedIISOS() {
				reason = "UNSUPPORTED_OS"
			}
			if reason == "" {
				record, e := readSNI(b.Hostname, b.Port)
				if e != nil {
					reason = "OWNER_UNKNOWN"
				} else {
					store := iisStoreName(record.Store)
					b.CertificateStore = &store
					if store != "My" && store != "WebHosting" {
						reason = "UNSUPPORTED_STORE"
					} else {
						cert, e := storedCertificate(store, record.Hash)
						if e != nil {
							reason = "OLD_KEY_UNAVAILABLE"
						} else {
							b.Certificate = iisCertificateSummary(cert)
						}
					}
				}
			}
			b.Eligible = reason == ""
			if reason != "" {
				b.Reason = &reason
			}
			r.Bindings = append(r.Bindings, b)
		}
	}
	if err := a.client.submitScan(req.ScanID, scanResult{Status: "SUCCESS", Sites: []scanSite{}, IIS: &r}); err != nil {
		log.Printf("report IIS scan: %v", err)
	}
}

func readIISSelection(siteID uint64, information string) (*iisSnapshot, *x509.Certificate, error) {
	if !supportedIISOS() {
		return nil, nil, errors.New("UNSUPPORTED_OS: requires Windows Server 2016, 2019, 2022 or 2025 amd64")
	}
	bindings, err := readIISBindings()
	if err != nil {
		return nil, nil, err
	}
	mappings, err := readIPMappings()
	if err != nil {
		return nil, nil, err
	}
	for _, b := range bindings {
		if b.SiteID != siteID || b.BindingInformation != information {
			continue
		}
		if reason := iisOwnership(b, bindings, mappings); reason != "" {
			return nil, nil, errors.New(reason)
		}
		record, err := readSNI(b.Hostname, b.Port)
		if err != nil {
			return nil, nil, err
		}
		s := &iisSnapshot{Record: record, SiteID: siteID, BindingInformation: information, SSLFlags: b.SSLFlags}
		store := iisStoreName(record.Store)
		if store != "My" && store != "WebHosting" {
			return s, nil, errors.New("UNSUPPORTED_STORE")
		}
		cert, err := storedCertificate(store, record.Hash)
		if err != nil {
			return s, nil, fmt.Errorf("OLD_KEY_UNAVAILABLE: %w", err)
		}
		return s, cert, nil
	}
	return nil, nil, errors.New("OWNER_UNKNOWN: selected IIS binding no longer exists")
}

func (a *agent) finishIIS(attemptID string, r result, binding string) (*journal, error) {
	j := journal{AttemptID: attemptID, Phase: "finished", Result: &r}
	if r.Status == "SUCCESS" {
		j.BindingInformation = binding
	}
	if err := a.journal.save(j); err != nil {
		return nil, fmt.Errorf("save finished journal: %w", err)
	}
	return &j, nil
}

func (a *agent) deployIIS(t task) (*journal, error) {
	fail := func(code string, err error) (*journal, error) {
		return a.finishIIS(t.AttemptID, result{Status: "FAILED", Error: code, Message: failureMessage(err)}, "")
	}
	if t.Type != "IIS" || t.IIS == nil || len(t.Files) != 0 || t.PostCommand != nil || t.OnePanel != nil || t.NPM != nil {
		return fail("UNSUPPORTED_TASK", errors.New("Windows supports IIS tasks only"))
	}
	spec := *t.IIS
	expected, err := hex.DecodeString(spec.FingerprintSha256)
	if err != nil || len(expected) != 32 {
		return fail("INTERNAL", errors.New("invalid fingerprintSha256"))
	}
	old, cert, err := readIISSelection(spec.SiteID, spec.BindingInformation)
	if err != nil {
		return fail("IIS_BINDING_UNSUPPORTED", err)
	}
	store := iisStoreName(old.Record.Store)
	details := iisCertificateResult(cert, store, false)
	if details.FingerprintSha256 == spec.FingerprintSha256 {
		return a.finishIIS(t.AttemptID, result{Status: "SUCCESS", IIS: details}, spec.BindingInformation)
	}
	cert, err = importIISCertificate(spec, store)
	if err != nil {
		return fail("IIS_API_FAILED", err)
	}
	details = iisCertificateResult(cert, store, true)
	hash, _ := hex.DecodeString(details.ThumbprintSha1)
	prepared := journal{AttemptID: t.AttemptID, Phase: "prepared", Snapshot: old, NewHash: hash, NewStore: old.Record.Store}
	if err := a.journal.save(prepared); err != nil {
		return nil, fmt.Errorf("save prepared journal: %w", err)
	}
	current, _, err := readIISSelection(spec.SiteID, spec.BindingInformation)
	if err != nil {
		return fail("IIS_STATE_CHANGED", fmt.Errorf("pre-update check failed; binding was not changed: %w", err))
	}
	if classifyIIS(prepared, current) != "OLD" {
		return fail("IIS_STATE_CHANGED", errors.New("binding changed before update; no write performed"))
	}
	next := iisNewSnapshot(prepared)
	if err := updateSNI(next.Record); err != nil {
		return a.recoverIIS(prepared, "IIS_API_FAILED", err.Error())
	}
	current, _, err = readIISSelection(spec.SiteID, spec.BindingInformation)
	if err != nil {
		return a.recoverIIS(prepared, "IIS_API_FAILED", err.Error())
	}
	if !reflect.DeepEqual(*current, next) {
		return a.recoverIIS(prepared, "IIS_API_FAILED", "update readback differs from expected state")
	}
	// 只有这个持久化成功后才提交，之后 TLS 不符也不撤销部署。
	return a.finishIIS(t.AttemptID, result{Status: "SUCCESS", IIS: details}, spec.BindingInformation)
}

func (a *agent) recoverIIS(j journal, cause, message string) (*journal, error) {
	current, _, err := readIISSelection(j.Snapshot.SiteID, j.Snapshot.BindingInformation)
	r := result{Status: "FAILED", Error: cause, Message: message}
	if err != nil {
		r.Error = "IIS_STATE_CHANGED"
		r.Message = "cannot safely recover; no write performed, check binding manually: " + err.Error()
	} else {
		switch iisRecoveryAction(j, current) {
		case "FAIL_OLD":
			r.Message = "original binding is unchanged; " + message
		case "FAIL_THIRD":
			r.Error = "IIS_STATE_CHANGED"
			r.Message = fmt.Sprintf("binding or HTTP.sys base parameters changed; no write performed, check manually (current SHA-1=%x, old=%x, intended=%x, sslFlags=%d, original=%d)", current.Record.Hash, j.Snapshot.Record.Hash, j.NewHash, current.SSLFlags, j.Snapshot.SSLFlags)
		case "ROLLBACK":
			if _, err = storedCertificate(iisStoreName(j.Snapshot.Record.Store), j.Snapshot.Record.Hash); err == nil {
				err = updateSNI(j.Snapshot.Record)
			}
			if err == nil {
				current, _, err = readIISSelection(j.Snapshot.SiteID, j.Snapshot.BindingInformation)
				if err == nil && !reflect.DeepEqual(current, j.Snapshot) {
					err = errors.New("rollback readback differs from original state")
				}
			}
			if err != nil {
				r.Error = "IIS_ROLLBACK_FAILED"
				r.Message = "manual intervention required: " + err.Error()
			} else {
				r.Status = "ROLLED_BACK"
				r.Message = "original binding restored; " + message
			}
		}
	}
	r.Message = failureMessage(errors.New(r.Message))
	return a.finishIIS(j.AttemptID, r, "")
}

func (a *agent) recoverPending() error {
	j, err := a.journal.load()
	if err != nil || j == nil {
		return err
	}
	switch j.Phase {
	case "prepared":
		if j.Snapshot == nil {
			return errors.New("prepared IIS journal has no snapshot")
		}
		j, err = a.recoverIIS(*j, "IIS_INTERRUPTED", "deployment interrupted before commit")
		if err != nil {
			return err
		}
	case "finished":
		if j.Result == nil {
			return errors.New("finished IIS journal has no result")
		}
	default:
		return fmt.Errorf("unsupported IIS journal phase %q", j.Phase)
	}
	return a.reportIIS(*j)
}

func (a *agent) execute(t task) error {
	var stale atomic.Bool
	stop := make(chan struct{})
	defer close(stop)
	go a.keepLease(t.AttemptID, stop, &stale)
	j, err := a.deployIIS(t)
	if err != nil {
		return err
	}
	return a.reportIIS(*j)
}

func (a *agent) reportIIS(j journal) error {
	r := *j.Result
	log.Printf("IIS deployment %s: %s %s %s", j.AttemptID, r.Status, r.Error, r.Message)
	if r.Status == "SUCCESS" {
		if r.IIS == nil {
			return errors.New("successful IIS journal has no certificate result")
		}
		ip, host, port, err := parseIISBinding(j.BindingInformation)
		if err != nil {
			return err
		}
		if ip == "*" || ip == "" || net.ParseIP(ip).IsUnspecified() {
			ip = "127.0.0.1"
		}
		raw, err := hex.DecodeString(r.IIS.FingerprintSha256)
		if err != nil || len(raw) != 32 {
			return errors.New("invalid IIS journal fingerprint")
		}
		r.LiveCheck = waitLive([]liveProbe{{address: net.JoinHostPort(ip, strconv.Itoa(int(port))), serverName: host, expected: [32]byte(raw)}})
	}
	wait := time.Second
	for {
		err := a.client.submitResult(j.AttemptID, r)
		var apiErr *apiError
		if err == nil || errors.As(err, &apiErr) && apiErr.Code == codeAttemptStale {
			return a.journal.remove()
		}
		if a.client.ctx.Err() != nil {
			return a.client.ctx.Err()
		}
		if apiErr != nil && apiErr.Code == codeCredentialInvalid {
			return err
		}
		log.Printf("report IIS result for %s: %v", j.AttemptID, err)
		delay := jitter(wait)
		if apiErr != nil && apiErr.Code == codeHostInactive {
			delay = inactiveWait
		}
		if err := a.wait(delay); err != nil {
			return err
		}
		wait = min(wait*2, 15*time.Second)
	}
}
