package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// 部署必须要么完整替换，要么让文件保持原样

func setup(t *testing.T) (string, journalStore) {
	dir := t.TempDir()
	return dir, journalStore{path: filepath.Join(dir, "journal.json")}
}

func readOrMissing(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<missing>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func noCommand(string) error { return nil }

func TestWriteFailureRestoresOriginals(t *testing.T) {
	dir, store := setup(t)
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "new.key")
	os.WriteFile(cert, []byte("old cert"), 0o640)

	r, err := apply(store, "a1", []fileSpec{
		{cert, []byte("new cert")},
		{key, []byte("new key")},
		{filepath.Join(dir, "missing-dir", "chain.pem"), []byte("chain")},
	}, "", noCommand)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "ROLLED_BACK" || r.Error != "FILE_WRITE_FAILED" {
		t.Fatalf("got %+v", r)
	}
	if got := readOrMissing(t, cert); got != "old cert" {
		t.Fatalf("cert = %q", got)
	}
	if got := readOrMissing(t, key); got != "<missing>" {
		t.Fatalf("key = %q, want removed", got)
	}
}

func TestUnreadableFileWritesNothing(t *testing.T) {
	dir, store := setup(t)
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("old cert"), 0o640)
	asDir := filepath.Join(dir, "key-is-a-dir")
	os.Mkdir(asDir, 0o700)

	r, _ := apply(store, "a1", []fileSpec{
		{cert, []byte("new cert")},
		{asDir, []byte("new key")},
	}, "reload", func(string) error { t.Fatal("post command must not run"); return nil })
	if r.Status != "FAILED" || r.Error != "FILE_READ_FAILED" {
		t.Fatalf("got %+v", r)
	}
	if got := readOrMissing(t, cert); got != "old cert" {
		t.Fatalf("cert = %q", got)
	}
}

func TestPostCommandFailureRestoresAndRerunsCommand(t *testing.T) {
	dir, store := setup(t)
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("old cert"), 0o640)

	var calls []string
	r, _ := apply(store, "a1", []fileSpec{{cert, []byte("new cert")}}, "reload", func(cmd string) error {
		calls = append(calls, readOrMissing(t, cert))
		if len(calls) == 1 {
			return errors.New("exit 1")
		}
		return nil
	})
	if r.Status != "ROLLED_BACK" || r.Error != "POST_COMMAND_FAILED" {
		t.Fatalf("got %+v", r)
	}
	if len(calls) != 2 || calls[0] != "new cert" || calls[1] != "old cert" {
		t.Fatalf("post command saw %v, want new then old", calls)
	}
}

func TestSecondPostCommandFailureIsReported(t *testing.T) {
	dir, store := setup(t)
	cert := filepath.Join(dir, "cert.pem")
	os.WriteFile(cert, []byte("old cert"), 0o640)

	r, _ := apply(store, "a1", []fileSpec{{cert, []byte("new cert")}}, "reload", func(string) error {
		return errors.New("exit 1")
	})
	if r.Status != "FAILED" || r.Error != "ROLLBACK_POST_COMMAND_FAILED" {
		t.Fatalf("got %+v", r)
	}
	if got := readOrMissing(t, cert); got != "old cert" {
		t.Fatalf("cert = %q", got)
	}
}

func TestRecoveryAfterCrashRestoresOriginals(t *testing.T) {
	dir, store := setup(t)
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "cert.key")
	os.WriteFile(cert, []byte("old cert"), 0o640)

	// 模拟写到一半崩溃：恢复记录已落盘，证书已被改写，私钥是新建的
	store.save(journal{AttemptID: "a1", Phase: "applying", PostCommand: "reload", Backups: []backup{
		{Path: cert, Existed: true, Content: []byte("old cert")},
		{Path: key},
	}})
	os.WriteFile(cert, []byte("half"), 0o640)
	os.WriteFile(key, []byte("new key"), 0o640)

	ran := 0
	j, err := recoverJournal(store, func(string) error { ran++; return nil })
	if err != nil || j != nil {
		t.Fatalf("recover: %v %v", j, err)
	}
	if got := readOrMissing(t, cert); got != "old cert" {
		t.Fatalf("cert = %q", got)
	}
	if got := readOrMissing(t, key); got != "<missing>" {
		t.Fatalf("key = %q", got)
	}
	if ran != 1 {
		t.Fatalf("post command ran %d times", ran)
	}
	if left, _ := store.load(); left != nil {
		t.Fatal("journal should be removed")
	}
}
