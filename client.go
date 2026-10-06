package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 与平台 packages/shared/src/error-codes.ts 保持一致
const (
	codeHostInactive      = 47003
	codeCredentialInvalid = 47005
	codeAttemptStale      = 47006
)

type agentInfo struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type taskFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"contentBase64"`
}

type task struct {
	AttemptID   string     `json:"attemptId"`
	Label       string     `json:"label"`
	Files       []taskFile `json:"files"`
	PostCommand *string    `json:"postCommand"`
}

type pollResponse struct {
	Task         *task   `json:"task"`
	RetryAfterMs float64 `json:"retryAfterMs"`
}

// apiError 是平台明确返回的业务错误，区别于网络错误
type apiError struct {
	Code    int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (code %d)", e.Message, e.Code) }

type client struct {
	server     string
	credential string
	poller     *http.Client
	http       *http.Client
}

func newClient(server, credential string) *client {
	return &client{
		server:     strings.TrimRight(server, "/"),
		credential: credential,
		// 平台最多挂起 50 秒，超时要比它长，否则会在领取后丢掉响应
		poller: &http.Client{Timeout: 80 * time.Second},
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *client) call(hc *http.Client, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.server+"/api/agent/v1"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lapsezero-agent/"+version)
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}
	if envelope.Code != 0 {
		return &apiError{Code: envelope.Code, Message: envelope.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Data, out)
}

func (c *client) enroll(token string, info agentInfo) (string, error) {
	var out struct {
		Credential string `json:"credential"`
	}
	body := struct {
		agentInfo
		Token string `json:"token"`
	}{info, token}
	if err := c.call(c.http, "/enroll", body, &out); err != nil {
		return "", err
	}
	return out.Credential, nil
}

func (c *client) poll(info agentInfo) (pollResponse, error) {
	var out pollResponse
	err := c.call(c.poller, "/poll", info, &out)
	return out, err
}

func (c *client) renewLease(attemptID string) error {
	return c.call(c.http, "/attempts/"+attemptID+"/lease", struct{}{}, nil)
}

func (c *client) submitResult(attemptID string, r result) error {
	return c.call(c.http, "/attempts/"+attemptID+"/result", r, nil)
}
