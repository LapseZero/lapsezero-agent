package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type updateFixture struct {
	u      *updater
	exits  []int
	oldBin []byte
}

func newUpdateFixture(t *testing.T, current string) *updateFixture {
	t.Helper()
	oldVersion := version
	version = current
	t.Cleanup(func() { version = oldVersion })

	dir := t.TempDir()
	f := &updateFixture{oldBin: []byte("#!/bin/sh\necho " + current + "\n")}
	exe := filepath.Join(dir, "lapsezero-agent")
	if err := os.WriteFile(exe, f.oldBin, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.u = &updater{
		exe:       exe,
		stateDir:  stateDir,
		http:      http.DefaultClient,
		exit:      func(code int) { f.exits = append(f.exits, code) },
		startedAt: time.Now(),
	}
	return f
}

// 起一个假的 Release：二进制是会报出 reported 版本的脚本，SHA256SUMS 用 key 签名
func serveRelease(t *testing.T, reported string, key ed25519.PrivateKey) string {
	t.Helper()
	bin := []byte("#!/bin/sh\necho " + reported + "\n")
	sum := sha256.Sum256(bin)
	name := "lapsezero-agent-linux-" + runtime.GOARCH
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, sums))
	mux := http.NewServeMux()
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, _ *http.Request) { w.Write(bin) })
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { w.Write(sums) })
	mux.HandleFunc("/SHA256SUMS.sig", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(sig + "\n")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func trustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releasePublicKey
	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { releasePublicKey = old })
	return priv
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestApplyInstallsSignedUpdateAndKeepsPrevious(t *testing.T) {
	f := newUpdateFixture(t, "v1.0.0")
	url := serveRelease(t, "v1.1.0", trustKey(t))

	f.u.apply(updateInfo{Version: "v1.1.0", ReleaseURL: url})

	if len(f.exits) != 1 {
		t.Fatalf("expected a restart, exits=%v", f.exits)
	}
	if got := mustRead(t, f.u.exe); got != "#!/bin/sh\necho v1.1.0\n" {
		t.Fatalf("binary not replaced: %q", got)
	}
	if got := mustRead(t, f.u.prevPath()); got != string(f.oldBin) {
		t.Fatalf("previous binary not kept: %q", got)
	}
	var m updateMarker
	if ok, err := readJSON(f.u.markerPath(), &m); !ok || err != nil || m.From != "v1.0.0" || m.To != "v1.1.0" {
		t.Fatalf("marker = %+v ok=%v err=%v", m, ok, err)
	}
}

func TestApplyRejectsUntrustedOrMislabelledRelease(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"signed by another key": func(t *testing.T) string {
			trustKey(t)
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			return serveRelease(t, "v1.1.0", other)
		},
		"binary reports another version": func(t *testing.T) string {
			return serveRelease(t, "v1.0.5", trustKey(t))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newUpdateFixture(t, "v1.0.0")
			f.u.apply(updateInfo{Version: "v1.1.0", ReleaseURL: setup(t)})
			if len(f.exits) != 0 || mustRead(t, f.u.exe) != string(f.oldBin) ||
				exists(f.u.markerPath()) || exists(f.u.prevPath()) || exists(f.u.newPath()) {
				t.Fatal("rejected update left changes behind")
			}
		})
	}
}

func TestNewVersionRollsBackAfterRepeatedFailedStarts(t *testing.T) {
	f := newUpdateFixture(t, "v1.1.0")
	if err := os.WriteFile(f.u.prevPath(), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(f.u.markerPath(), updateMarker{From: "v1.0.0", To: "v1.1.0"}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxUpdateStarts; i++ {
		if err := f.u.checkPending(); err != nil {
			t.Fatal(err)
		}
		if len(f.exits) != 0 || f.u.pending == nil {
			t.Fatalf("start %d should keep running the new version", i+1)
		}
	}
	if err := f.u.checkPending(); err != nil {
		t.Fatal(err)
	}

	if len(f.exits) != 1 || mustRead(t, f.u.exe) != "old" || exists(f.u.markerPath()) {
		t.Fatalf("expected rollback to the previous binary, exits=%v", f.exits)
	}
	var failed failedUpdate
	if ok, _ := readJSON(f.u.failedPath(), &failed); !ok || failed.Version != "v1.1.0" {
		t.Fatalf("failed version not recorded: %+v", failed)
	}
}

func TestNewVersionRollsBackWhenItNeverReachesThePlatform(t *testing.T) {
	f := newUpdateFixture(t, "v1.1.0")
	os.WriteFile(f.u.prevPath(), []byte("old"), 0o755)
	writeJSON(f.u.markerPath(), updateMarker{From: "v1.0.0", To: "v1.1.0"})
	if err := f.u.checkPending(); err != nil {
		t.Fatal(err)
	}

	f.u.checkDeadline()
	if len(f.exits) != 0 {
		t.Fatal("rolled back before the deadline")
	}
	f.u.startedAt = time.Now().Add(-updateConfirmTimeout - time.Second)
	f.u.checkDeadline()
	if len(f.exits) != 1 || mustRead(t, f.u.exe) != "old" {
		t.Fatal("expected rollback after the deadline")
	}
}

func TestConfirmKeepsNewVersion(t *testing.T) {
	f := newUpdateFixture(t, "v1.1.0")
	os.WriteFile(f.u.prevPath(), []byte("old"), 0o755)
	writeJSON(f.u.markerPath(), updateMarker{From: "v1.0.0", To: "v1.1.0"})
	if err := f.u.checkPending(); err != nil {
		t.Fatal(err)
	}

	f.u.confirm()
	f.u.startedAt = time.Now().Add(-updateConfirmTimeout - time.Second)
	f.u.checkDeadline()

	if len(f.exits) != 0 || exists(f.u.markerPath()) || exists(f.u.prevPath()) {
		t.Fatal("confirmed update should be kept and cleaned up")
	}
}

func TestStaleMarkerIsDiscarded(t *testing.T) {
	f := newUpdateFixture(t, "v1.0.0")
	os.WriteFile(f.u.prevPath(), []byte("old"), 0o755)
	writeJSON(f.u.markerPath(), updateMarker{From: "v1.0.0", To: "v1.1.0", Starts: maxUpdateStarts})

	if err := f.u.checkPending(); err != nil {
		t.Fatal(err)
	}
	if len(f.exits) != 0 || f.u.pending != nil || exists(f.u.markerPath()) || mustRead(t, f.u.exe) != string(f.oldBin) {
		t.Fatal("a marker for another version must not trigger a rollback")
	}
}

func TestFailedVersionIsSkippedForADay(t *testing.T) {
	f := newUpdateFixture(t, "v1.0.0")
	url := serveRelease(t, "v1.1.0", trustKey(t))
	writeJSON(f.u.failedPath(), failedUpdate{Version: "v1.1.0", At: time.Now()})

	f.u.apply(updateInfo{Version: "v1.1.0", ReleaseURL: url})
	if len(f.exits) != 0 {
		t.Fatal("recently failed version should be skipped")
	}

	writeJSON(f.u.failedPath(), failedUpdate{Version: "v1.1.0", At: time.Now().Add(-failedUpdateRetry - time.Minute)})
	f.u.apply(updateInfo{Version: "v1.1.0", ReleaseURL: url})
	if len(f.exits) != 1 {
		t.Fatal("failed version should be retried after a day")
	}
}

func TestVersionNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.5.0", "v0.4.0", true},
		{"v0.10.0", "v0.9.9", true},
		{"v0.4.0", "v0.4.0", false},
		{"v0.3.9", "v0.4.0", false},
		{"v0.5.0", "dev", false},
		{"v0.5.0", "v0.4.0-3-gabc", false},
	} {
		if got := versionNewer(c.a, c.b); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
