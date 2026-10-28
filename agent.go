package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

const (
	leaseInterval      = 30 * time.Second
	postCommandTimeout = 5 * time.Minute
	maxBackoff         = time.Minute
	// 主机被停用时，等用户在控制台重新启用，不必频繁重试
	inactiveWait = 5 * time.Minute
	// 凭证失效说明主机已删除、已在别处重新注册或账户已注销，旧凭证不会再变回有效。
	// 安装脚本写入的 systemd 服务配置了 RestartPreventExitStatus，以这个码退出后不再被拉起
	exitRevoked = 3
)

type agent struct {
	client  *client
	journal journalStore
	info    agentInfo
	updater *updater
}

func (a *agent) run() {
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

	backoff := time.Duration(0)
	for {
		a.updater.checkDeadline()
		started := time.Now()
		resp, err := a.client.poll(a.info)
		var apiErr *apiError
		errors.As(err, &apiErr)
		// 平台认出了这个客户端才算新版本可用；参数错误、平台内部错误不算，请求格式不兼容时仍能换回
		if err == nil || apiErr != nil && (apiErr.Code == codeCredentialInvalid || apiErr.Code == codeHostInactive) {
			a.updater.confirm()
		}
		if err != nil {
			if apiErr != nil && apiErr.Code == codeCredentialInvalid {
				log.Printf("poll rejected: %v", apiErr)
				log.Printf("this agent has been deleted or re-enrolled in the LapseZero console, stopping. To remove it from this server, run `lapsezero-agent uninstall` as root")
				os.Exit(exitRevoked)
			}
			if apiErr != nil && apiErr.Code == codeHostInactive {
				log.Printf("poll rejected: %v", apiErr)
				time.Sleep(inactiveWait)
				continue
			}
			backoff = min(max(backoff*2, time.Second), maxBackoff)
			log.Printf("poll failed: %v, retrying in about %s", err, backoff)
			time.Sleep(jitter(backoff))
			continue
		}
		backoff = 0

		if resp.Scan != nil {
			a.scan(*resp.Scan)
			continue
		}
		if resp.Task == nil {
			if resp.Update != nil {
				a.updater.apply(*resp.Update)
			}
			wait := time.Duration(resp.RetryAfterMs) * time.Millisecond
			// 防止异常情况下立即返回的空响应造成忙等
			if wait == 0 && time.Since(started) < time.Second {
				wait = time.Second
			}
			time.Sleep(wait)
			continue
		}
		a.execute(*resp.Task)
	}
}

func (a *agent) execute(t task) {
	if t.OnePanel != nil {
		a.executeOnePanel(t)
		return
	}
	files := make([]fileSpec, 0, len(t.Files))
	for _, f := range t.Files {
		content, err := base64.StdEncoding.DecodeString(f.ContentBase64)
		if err != nil {
			a.report(t.AttemptID, result{Status: "FAILED", Error: "INTERNAL", Message: "invalid file content"})
			return
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
	if len(r.NPM) > 0 && r.Error == "NGINX_NOT_FOUND" {
		r.Status = "SUCCESS"
		r.Error = ""
		r.Sites = []scanSite{}
	}
	log.Printf("nginx scan finished: %s %s (%d sites)", r.Status, r.Error, len(r.Sites))
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

// 续租失败说明平台已不再等这次结果；继续把执行（含必要的回滚）做完，但不再上报
func (a *agent) keepLease(attemptID string, stop <-chan struct{}, stale *atomic.Bool) {
	ticker := time.NewTicker(leaseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			err := a.client.renewLease(attemptID)
			var apiErr *apiError
			if errors.As(err, &apiErr) && apiErr.Code == codeAttemptStale {
				log.Printf("attempt %s is no longer current on the platform", attemptID)
				stale.Store(true)
				return
			}
			if err != nil {
				log.Printf("renew lease: %v", err)
			}
		}
	}
}

// 网络失败时在租约有效期内重试；平台拒绝（不是当前尝试）就放弃
func (a *agent) report(attemptID string, r result) {
	deadline := time.Now().Add(90 * time.Second)
	wait := time.Second
	for {
		err := a.client.submitResult(attemptID, r)
		if err == nil {
			return
		}
		// 平台内部错误是暂时的，和网络失败一样重试
		var apiErr *apiError
		rejected := errors.As(err, &apiErr) && apiErr.Code != codeInternalError
		if rejected || time.Now().After(deadline) {
			log.Printf("report result for %s: %v", attemptID, err)
			return
		}
		time.Sleep(jitter(wait))
		wait = min(wait*2, 15*time.Second)
	}
}

func runPostCommand(command string) error {
	ctx, cancel := context.WithTimeout(context.Background(), postCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", command).CombinedOutput()
	if len(out) > 0 {
		log.Printf("post command output:\n%s", tail(out, 4096))
	}
	return err
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

// 抖动避免平台发布后所有客户端同时重连
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}
