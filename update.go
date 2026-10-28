package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// 对应发布者本机的签名私钥（tools/sign）；Release 的 SHA256SUMS 必须带这把钥匙的签名才会被自动更新接受
var releasePublicKey = "xpNHsV9Ve9IKSfrMHJCpsWjZ2HIO97hw9DmS+zWzwHo="

const (
	// 新版本连续启动这么多次都没能确认就换回旧版本；systemd 每 10 秒重启一次
	maxUpdateStarts = 3
	// 新版本启动后这么久还没和平台通上话，也换回旧版本
	updateConfirmTimeout = 5 * time.Minute
	// 换回过的版本隔一段时间再试，平台故障导致的误判不至于永久卡在旧版本
	failedUpdateRetry = 24 * time.Hour
	// 下载或校验失败后的等待，避免每次 poll 都重新下载
	updateErrorRetry = time.Hour
	maxBinarySize    = 100 << 20
)

// 退出码 0 让 systemd 重启进程（Restart=always），由新的二进制接着运行
const exitRestart = 0

// 平台在客户端版本落后时随 poll 响应下发
type updateInfo struct {
	Version    string `json:"version"`
	ReleaseURL string `json:"releaseUrl"`
}

// 替换二进制前落盘；新版本第一次 poll 成功后删除，删除前的每次启动都计数
type updateMarker struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Starts int    `json:"starts"`
}

type failedUpdate struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

type updater struct {
	exe      string
	stateDir string
	http     *http.Client
	exit     func(int)
	// 本次启动是刚更新上来的新版本、还没确认时才有
	pending   *updateMarker
	startedAt time.Time
	nextTry   time.Time
}

func newUpdater(stateDir string) (*updater, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, err
	}
	return &updater{
		exe:       exe,
		stateDir:  stateDir,
		http:      &http.Client{Timeout: 5 * time.Minute},
		exit:      os.Exit,
		startedAt: time.Now(),
	}, nil
}

func (u *updater) markerPath() string { return filepath.Join(u.stateDir, "update.json") }
func (u *updater) failedPath() string { return filepath.Join(u.stateDir, "update-failed.json") }
func (u *updater) prevPath() string   { return u.exe + ".prev" }
func (u *updater) newPath() string    { return u.exe + ".new" }

// 启动时调用，必须早于任何可能崩溃的初始化。连续启动失败时换回旧版本并退出，不会返回
func (u *updater) checkPending() error {
	var m updateMarker
	if ok, err := readJSON(u.markerPath(), &m); err != nil || !ok {
		return err
	}
	// 记录不是为当前版本写的（替换没完成，或用户重新安装过），作废
	if m.To != version {
		log.Printf("discarding update record from %s to %s, running %s", m.From, m.To, version)
		return u.clearPending()
	}
	m.Starts++
	if m.Starts > maxUpdateStarts {
		u.rollback(m, "it failed to start")
		return nil
	}
	if err := writeJSON(u.markerPath(), m); err != nil {
		return err
	}
	u.pending = &m
	log.Printf("updated from %s, waiting for the first successful poll (start %d of %d)", m.From, m.Starts, maxUpdateStarts)
	return nil
}

func (u *updater) confirm() {
	if u.pending == nil {
		return
	}
	log.Printf("update from %s to %s confirmed", u.pending.From, version)
	u.pending = nil
	if err := u.clearPending(); err != nil {
		log.Printf("clear update record: %v", err)
	}
}

// 在主循环里检查，避免和正在执行的部署并发换回
func (u *updater) checkDeadline() {
	if u.pending != nil && time.Since(u.startedAt) > updateConfirmTimeout {
		u.rollback(*u.pending, "it could not reach the platform")
	}
}

func (u *updater) rollback(m updateMarker, reason string) {
	log.Printf("rolling back from %s to %s because %s", m.To, m.From, reason)
	// 任何一步失败都保留更新记录退出，下次启动再试，不放弃回滚
	if err := writeJSON(u.failedPath(), failedUpdate{Version: m.To, At: time.Now()}); err != nil {
		log.Fatalf("record failed update: %v", err)
	}
	if err := os.Rename(u.prevPath(), u.exe); err != nil {
		log.Fatalf("restore previous binary: %v", err)
	}
	if err := removeIfExists(u.markerPath()); err != nil {
		log.Fatalf("clear update record: %v", err)
	}
	u.exit(exitRestart)
}

func (u *updater) clearPending() error {
	if err := removeIfExists(u.prevPath()); err != nil {
		return err
	}
	return removeIfExists(u.markerPath())
}

// 只在空闲时调用。更新成功会退出进程，由 systemd 用新二进制重启
func (u *updater) apply(info updateInfo) {
	if !versionNewer(info.Version, version) || time.Now().Before(u.nextTry) {
		return
	}
	var failed failedUpdate
	if ok, err := readJSON(u.failedPath(), &failed); err != nil {
		log.Printf("read failed update record: %v", err)
		return
	} else if ok && failed.Version == info.Version && time.Since(failed.At) < failedUpdateRetry {
		return
	}
	log.Printf("updating from %s to %s", version, info.Version)
	if err := u.install(info); err != nil {
		log.Printf("update to %s failed: %v", info.Version, err)
		u.nextTry = time.Now().Add(updateErrorRetry)
		return
	}
	log.Printf("installed %s, restarting", info.Version)
	u.exit(exitRestart)
}

func (u *updater) install(info updateInfo) error {
	binary := "lapsezero-agent-linux-" + runtime.GOARCH
	expected, err := u.verifiedChecksum(info.ReleaseURL, binary)
	if err != nil {
		return err
	}
	defer removeIfExists(u.newPath())
	if err := u.download(info.ReleaseURL+"/"+binary, u.newPath(), expected); err != nil {
		return err
	}
	// 签名的二进制自己报出的版本才可信，也能挡住拿旧版本冒充新版本
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, u.newPath(), "version").Output()
	if err != nil {
		return fmt.Errorf("run new binary: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != info.Version {
		return fmt.Errorf("new binary reports version %q", got)
	}
	if err := copyFile(u.exe, u.prevPath()); err != nil {
		return fmt.Errorf("keep previous binary: %w", err)
	}
	if err := writeJSON(u.markerPath(), updateMarker{From: version, To: info.Version}); err != nil {
		return err
	}
	if err := os.Rename(u.newPath(), u.exe); err != nil {
		if err := u.clearPending(); err != nil {
			log.Printf("clear update record: %v", err)
		}
		return err
	}
	return nil
}

func (u *updater) verifiedChecksum(releaseURL, binary string) (string, error) {
	sums, err := u.fetch(releaseURL + "/SHA256SUMS")
	if err != nil {
		return "", err
	}
	sig, err := u.fetch(releaseURL + "/SHA256SUMS.sig")
	if err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil {
		return "", err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, sums, sigBytes) {
		return "", errors.New("SHA256SUMS signature is invalid")
	}
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == binary {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%s is not listed in SHA256SUMS", binary)
}

func (u *updater) fetch(url string) ([]byte, error) {
	resp, err := u.http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (u *updater) download(url, path, expected string) error {
	resp, err := u.http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBinarySize))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("checksum mismatch")
	}
	return nil
}

var versionPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// 只认 vX.Y.Z；开发构建的版本解析不了，不参与自动更新
func versionNewer(candidate, current string) bool {
	a, b := versionPattern.FindStringSubmatch(candidate), versionPattern.FindStringSubmatch(current)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return false
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, data, 0o755)
}

func readJSON(path string, out any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, out)
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
