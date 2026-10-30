//go:build !windows

package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

const defaultConfigPath = "/etc/lapsezero-agent/config.json"
const defaultStateDir = "/var/lib/lapsezero-agent"

func platformCommand(string, []string) bool { return false }

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	stateDir := fs.String("state-dir", defaultStateDir, "directory for lock and recovery journal")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		log.Fatalf("create state dir: %v", err)
	}
	unlock, err := lockInstance(filepath.Join(*stateDir, "agent.lock"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer unlock()

	up, err := newUpdater(*stateDir)
	if err != nil {
		log.Fatalf("locate executable: %v", err)
	}
	if err := up.checkPending(); err != nil {
		log.Fatalf("check pending update: %v", err)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	a := &agent{
		client:  newClient(cfg.Server, cfg.Credential),
		journal: journalStore{path: filepath.Join(*stateDir, "journal.json")},
		info:    hostInfo(),
		updater: up,
	}
	log.Printf("lapsezero-agent %s started, server %s", version, cfg.Server)
	if err := a.run(); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Code == codeCredentialInvalid {
			os.Exit(exitRevoked)
		}
		log.Fatal(err)
	}
}

// 同一台机器只允许一个实例执行部署，否则两次执行可能交错写同一批文件
func lockInstance(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another lapsezero-agent instance is already running")
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
