// lapsezero-agent 运行在用户服务器上，通过出站 HTTPS 向 LapseZero 领取证书部署任务。
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// 构建时通过 -ldflags "-X main.version=..." 写入
var version = "dev"

const (
	defaultConfigPath = "/etc/lapsezero-agent/config.json"
	defaultStateDir   = "/var/lib/lapsezero-agent"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  lapsezero-agent enroll --server <url> --token <token> [--config <path>]
  lapsezero-agent run [--config <path>] [--state-dir <dir>]
  lapsezero-agent version`)
}

func hostInfo() agentInfo {
	return agentInfo{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "LapseZero site URL")
	token := fs.String("token", "", "one-time enrollment token from the console")
	configPath := fs.String("config", defaultConfigPath, "config file path")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		usage()
		os.Exit(2)
	}

	credential, err := newClient(*server, "").enroll(*token, hostInfo())
	if err != nil {
		log.Fatalf("enroll failed: %v", err)
	}
	if err := saveConfig(*configPath, config{Server: *server, Credential: credential}); err != nil {
		log.Fatalf("save config: %v", err)
	}
	log.Printf("enrolled, config saved to %s", *configPath)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	stateDir := fs.String("state-dir", defaultStateDir, "directory for lock and recovery journal")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		log.Fatalf("create state dir: %v", err)
	}
	unlock, err := lockInstance(filepath.Join(*stateDir, "agent.lock"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer unlock()

	a := &agent{
		client:  newClient(cfg.Server, cfg.Credential),
		journal: journalStore{path: filepath.Join(*stateDir, "journal.json")},
		info:    hostInfo(),
	}
	log.Printf("lapsezero-agent %s started, server %s", version, cfg.Server)
	a.run()
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
