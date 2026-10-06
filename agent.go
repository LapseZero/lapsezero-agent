package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"math/rand/v2"
	"os/exec"
	"sync/atomic"
	"time"
)

const (
	leaseInterval      = 30 * time.Second
	postCommandTimeout = 5 * time.Minute
	maxBackoff         = time.Minute
	// 凭证失效或主机被停用时，等用户在控制台处理，不必频繁重试
	unauthorizedWait = 5 * time.Minute
)

type agent struct {
	client  *client
	journal journalStore
	info    agentInfo
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
		started := time.Now()
		resp, err := a.client.poll(a.info)
		if err != nil {
			var apiErr *apiError
			if errors.As(err, &apiErr) && (apiErr.Code == codeCredentialInvalid || apiErr.Code == codeHostInactive) {
				log.Printf("poll rejected: %v", apiErr)
				time.Sleep(unauthorizedWait)
				continue
			}
			backoff = min(max(backoff*2, time.Second), maxBackoff)
			log.Printf("poll failed: %v, retrying in about %s", err, backoff)
			time.Sleep(jitter(backoff))
			continue
		}
		backoff = 0

		if resp.Task == nil {
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
	r, err := apply(a.journal, t.AttemptID, files, postCommand, runPostCommand)
	close(stop)
	if err != nil {
		r = result{Status: "FAILED", Error: "INTERNAL", Message: err.Error()}
	}
	log.Printf("deployment of %s finished: %s %s", t.Label, r.Status, r.Error)

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
		var apiErr *apiError
		if errors.As(err, &apiErr) || time.Now().After(deadline) {
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
