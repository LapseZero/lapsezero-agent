// lapsezero-agent 运行在用户服务器上，通过出站 HTTPS 向 LapseZero 领取证书部署任务。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
)

// 构建时通过 -ldflags "-X main.version=..." 写入
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if platformCommand(os.Args[1], os.Args[2:]) {
		return
	}
	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "uninstall":
		cmdUninstall()
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, `Usage (Administrator):
  lapsezero-agent.exe install --server <url> --token <token>
  lapsezero-agent.exe run
  lapsezero-agent.exe uninstall
  lapsezero-agent.exe version
Upgrade: download the release exe to a temporary directory and run install again.`)
		return
	}
	fmt.Fprintln(os.Stderr, `Usage:
  lapsezero-agent enroll --server <url> --token <token> [--config <path>]
  lapsezero-agent run [--config <path>] [--state-dir <dir>]
  lapsezero-agent uninstall
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
