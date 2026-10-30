//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const unitPath = "/etc/systemd/system/lapsezero-agent.service"

// 移除 install.sh 装下的全部内容。卸载前先停服务，再确认没有待恢复的部署，避免删掉还没还原的原文件
func cmdUninstall() {
	if os.Geteuid() != 0 {
		log.Fatalf("uninstall must run as root")
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("locate executable: %v", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		log.Fatalf("locate executable: %v", err)
	}

	systemctl("stop", "lapsezero-agent")
	journalPath := filepath.Join(defaultStateDir, "journal.json")
	if _, err := os.Stat(journalPath); err == nil {
		log.Fatalf("Uninstall stopped: a deployment was interrupted and its original files have not been restored yet (%s). Run `systemctl start lapsezero-agent` to restore them, then run uninstall again.", journalPath)
	}
	systemctl("disable", "lapsezero-agent")

	for _, path := range []string{unitPath, exe + ".prev", exe + ".new", exe} {
		if err := removeIfExists(path); err != nil {
			log.Fatalf("remove %s: %v", path, err)
		}
	}
	for _, dir := range []string{filepath.Dir(defaultConfigPath), defaultStateDir} {
		if err := os.RemoveAll(dir); err != nil {
			log.Fatalf("remove %s: %v", dir, err)
		}
	}
	systemctl("daemon-reload")
	fmt.Println("lapsezero-agent has been removed from this server.")
}

func systemctl(args ...string) {
	if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
		log.Fatalf("systemctl %v: %v %s\nUninstall stopped. Check the service with `systemctl status lapsezero-agent`, then try again.", args, err, out)
	}
}
