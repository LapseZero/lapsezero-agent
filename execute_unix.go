//go:build !windows

package main

import (
	"encoding/base64"
	"log"
	"sync/atomic"
)

func (a *agent) recoverPending() error {
	if j, err := recoverJournal(a.journal, func(cmd string) error {
		log.Printf("restored files from an interrupted deployment, running the post command again")
		return runPostCommand(cmd)
	}); err != nil {
		// 恢复失败时保留恢复记录，避免新部署覆盖掉还没恢复的原文件
		log.Fatalf("recover previous deployment: %v", err)
	} else if j != nil {
		a.report(j.AttemptID, *j.Result)
		if err := a.journal.remove(); err != nil {
			log.Fatalf("remove journal: %v", err)
		}
	}

	return nil
}

func (a *agent) execute(t task) error {
	if t.Type != "" || t.IIS != nil {
		a.report(t.AttemptID, result{Status: "FAILED", Error: "UNSUPPORTED_TASK", Message: "unsupported task type"})
		return nil
	}
	if t.OnePanel != nil {
		a.executeOnePanel(t)
		return nil
	}
	files := make([]fileSpec, 0, len(t.Files))
	for _, f := range t.Files {
		content, err := base64.StdEncoding.DecodeString(f.ContentBase64)
		if err != nil {
			a.report(t.AttemptID, result{Status: "FAILED", Error: "INTERNAL", Message: "invalid file content"})
			return nil
		}
		files = append(files, fileSpec{Path: f.Path, Content: content})
	}
	postCommand := ""
	if t.PostCommand != nil {
		postCommand = *t.PostCommand
	}
	log.Printf("deploying %s (%d files)", t.Label, len(files))

	var stale atomic.Bool
	stop := make(chan struct{})
	go a.keepLease(t.AttemptID, stop, &stale)
	var r result
	var err error
	if t.NPM != nil {
		r, err = deployNpm(*t.NPM)
	} else {
		r, err = apply(a.journal, t.AttemptID, files, postCommand, runPostCommand)
	}
	if t.NPM == nil && err == nil && r.Status == "SUCCESS" {
		r.LiveCheck = checkLive(files)
		if r.LiveCheck == nil {
			r.LiveCheck = checkApacheLive(files)
		}
	}
	close(stop)
	if err != nil {
		r = result{Status: "FAILED", Error: "INTERNAL", Message: err.Error()}
	}
	log.Printf("deployment of %s finished: %s %s", t.Label, r.Status, r.Error)
	if r.LiveCheck != nil {
		log.Printf("live check on %s (%s): %s %s", r.LiveCheck.Address, r.LiveCheck.ServerName, r.LiveCheck.Status, r.LiveCheck.ErrorCode)
	}

	if err == nil {
		// 结果可能送不到平台，先记下来，重启后补报
		if err := a.journal.save(journal{AttemptID: t.AttemptID, Phase: "finished", Result: &r}); err != nil {
			log.Printf("save journal: %v", err)
		}
	}
	if !stale.Load() {
		a.report(t.AttemptID, r)
	}
	if err := a.journal.remove(); err != nil {
		log.Fatalf("remove journal: %v", err)
	}
	return nil
}

// 1Panel 部署只调用一次面板 API，没有要恢复的文件，不写恢复记录
func (a *agent) executeOnePanel(t task) {
	log.Printf("deploying %s to 1Panel certificate %d", t.Label, t.OnePanel.SslID)
	var stale atomic.Bool
	stop := make(chan struct{})
	go a.keepLease(t.AttemptID, stop, &stale)
	r := deployOnePanel(*t.OnePanel)
	close(stop)
	log.Printf("deployment of %s finished: %s %s %s", t.Label, r.Status, r.Error, r.Message)
	if r.LiveCheck != nil {
		log.Printf("live check on %s (%s): %s %s", r.LiveCheck.Address, r.LiveCheck.ServerName, r.LiveCheck.Status, r.LiveCheck.ErrorCode)
	}
	if !stale.Load() {
		a.report(t.AttemptID, r)
	}
}

// 扫描只读，失败了用户在控制台重新扫描即可，所以上报只尝试一次
func (a *agent) scan(req scanRequest) {
	r := scanNginx()
	r.NPM = scanNpm(req.NPMCredentials)
	r.Apache = scanApache()
	if (len(r.NPM) > 0 || r.Apache != nil) && r.Error == "NGINX_NOT_FOUND" {
		r.Status = "SUCCESS"
		r.Error = ""
		r.Sites = []scanSite{}
	}
	log.Printf("nginx scan finished: %s %s (%d sites)", r.Status, r.Error, len(r.Sites))
	if r.Apache != nil {
		log.Printf("apache scan finished: %s %s (%d sites)", r.Apache.Status, r.Apache.Error, len(r.Apache.Sites))
	}
	if addr := onePanelAddress(); addr != "" {
		r.OnePanel = scanOnePanel(addr, req.OnePanelAPIKey)
		log.Printf("1Panel scan finished: %s %s (%d sites)", r.OnePanel.Status, r.OnePanel.Message, len(r.OnePanel.Sites))
		// 1Panel 的 OpenResty 在容器里，宿主机上本来就没有 Nginx
		if r.Status == "FAILED" && r.Error == "NGINX_NOT_FOUND" {
			r = scanResult{Status: "SUCCESS", Sites: []scanSite{}, OnePanel: r.OnePanel}
		}
	}
	if err := a.client.submitScan(req.ScanID, r); err != nil {
		log.Printf("report scan result: %v", err)
	}
}
