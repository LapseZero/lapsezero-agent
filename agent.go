package main

import (
	"context"
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

func (a *agent) run() error {
	if err := a.recoverPending(); err != nil {
		return err
	}

	backoff := time.Duration(0)
	for {
		if a.updater != nil {
			a.updater.checkDeadline()
		}
		started := time.Now()
		resp, err := a.client.poll(a.info)
		var apiErr *apiError
		errors.As(err, &apiErr)
		// 平台认出了这个客户端才算新版本可用；参数错误、平台内部错误不算，请求格式不兼容时仍能换回
		if err == nil || apiErr != nil && (apiErr.Code == codeCredentialInvalid || apiErr.Code == codeHostInactive) {
			if a.updater != nil {
				a.updater.confirm()
			}
		}
		if err != nil {
			if a.client.ctx.Err() != nil {
				return a.client.ctx.Err()
			}
			if apiErr != nil && apiErr.Code == codeCredentialInvalid {
				log.Printf("poll rejected: %v", apiErr)
				log.Printf("this agent has been deleted or re-enrolled in the LapseZero console, stopping. To remove it from this server, run `lapsezero-agent uninstall` as root")
				return err
			}
			if apiErr != nil && apiErr.Code == codeHostInactive {
				log.Printf("poll rejected: %v", apiErr)
				if err := a.wait(inactiveWait); err != nil {
					return err
				}
				continue
			}
			backoff = min(max(backoff*2, time.Second), maxBackoff)
			log.Printf("poll failed: %v, retrying in about %s", err, backoff)
			if err := a.wait(jitter(backoff)); err != nil {
				return err
			}
			continue
		}
		backoff = 0

		if resp.Scan != nil {
			a.scan(*resp.Scan)
			continue
		}
		if resp.Task == nil {
			if resp.Update != nil {
				if a.updater != nil {
					a.updater.apply(*resp.Update)
				}
			}
			wait := time.Duration(resp.RetryAfterMs) * time.Millisecond
			// 防止异常情况下立即返回的空响应造成忙等
			if wait == 0 && time.Since(started) < time.Second {
				wait = time.Second
			}
			if err := a.wait(wait); err != nil {
				return err
			}
			continue
		}
		if err := a.execute(*resp.Task); err != nil {
			return err
		}
	}
}

// 续租返回 STALE 后停止续租；执行仍做完，是否补报由平台执行入口决定。
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
	if err != nil && len(out) > 0 {
		// 平台把输出展示给用户排查，退出状态放在最后，截断时保留
		return errors.New(string(out) + "\n" + err.Error())
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

func (a *agent) wait(d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-a.client.ctx.Done():
		return a.client.ctx.Err()
	}
}
