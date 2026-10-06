package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// 与平台 agentResultSchema 一致
type result struct {
	Status  string   `json:"status"`
	Error   string   `json:"error,omitempty"`
	Files   []string `json:"files,omitempty"`
	Message string   `json:"message,omitempty"`
}

type fileSpec struct {
	Path    string
	Content []byte
}

type backup struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Content []byte `json:"content,omitempty"`
}

// journal 在写文件前落盘，进程崩溃后据此把文件恢复成原内容
type journal struct {
	AttemptID   string   `json:"attemptId"`
	Phase       string   `json:"phase"` // applying | finished
	PostCommand string   `json:"postCommand,omitempty"`
	Backups     []backup `json:"backups,omitempty"`
	Result      *result  `json:"result,omitempty"`
}

type journalStore struct{ path string }

func (s journalStore) save(j journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s journalStore) load() (*journal, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s journalStore) remove() error {
	err := os.Remove(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// apply 与平台的 SSH 部署语义一致：要么全部替换，要么保持原样。
// 写前读出全部原文件（任何一个读不到就一个都不写），原地写入，全部写完才执行后置命令；
// 失败时恢复原内容，后置命令失败恢复后再执行一次，让服务回到旧证书。
func apply(store journalStore, attemptID string, files []fileSpec, postCommand string, run func(string) error) (result, error) {
	var backups []backup
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		content, err := os.ReadFile(f.Path)
		switch {
		case err == nil:
			backups = append(backups, backup{Path: f.Path, Existed: true, Content: content})
		case errors.Is(err, fs.ErrNotExist):
			backups = append(backups, backup{Path: f.Path})
		default:
			return result{Status: "FAILED", Error: "FILE_READ_FAILED"}, nil
		}
	}

	// 恢复记录写不下去就不能保证崩溃后可恢复，按内部错误放弃，一个文件都不写
	if err := store.save(journal{AttemptID: attemptID, Phase: "applying", PostCommand: postCommand, Backups: backups}); err != nil {
		return result{}, err
	}

	var touched []string
	for _, f := range files {
		if err := writeInPlace(f.Path, f.Content, func() { touched = append(touched, f.Path) }); err != nil {
			if unrestored := restore(backups, touched); len(unrestored) > 0 {
				return result{Status: "FAILED", Error: "ROLLBACK_FAILED", Files: unrestored}, nil
			}
			return result{Status: "ROLLED_BACK", Error: "FILE_WRITE_FAILED"}, nil
		}
	}

	if postCommand != "" {
		if err := run(postCommand); err != nil {
			if unrestored := restore(backups, touched); len(unrestored) > 0 {
				return result{Status: "FAILED", Error: "ROLLBACK_FAILED", Files: unrestored}, nil
			}
			if err := run(postCommand); err != nil {
				return result{Status: "FAILED", Error: "ROLLBACK_POST_COMMAND_FAILED"}, nil
			}
			return result{Status: "ROLLED_BACK", Error: "POST_COMMAND_FAILED"}, nil
		}
	}
	return result{Status: "SUCCESS"}, nil
}

// 原地写入而不是写临时文件再 rename，以保留文件属主和软链接
func writeInPlace(path string, content []byte, onOpen func()) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	// 文件一打开就被截断，写到一半失败的文件也要恢复
	onOpen()
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// 尽量恢复每个文件，返回没能恢复的路径
func restore(backups []backup, paths []string) []string {
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	var unrestored []string
	for _, b := range backups {
		if !want[b.Path] {
			continue
		}
		var err error
		if b.Existed {
			err = writeInPlace(b.Path, b.Content, func() {})
		} else if err = os.Remove(b.Path); errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		if err != nil {
			unrestored = append(unrestored, b.Path)
		}
	}
	return unrestored
}

// recoverJournal 在启动时处理上次没走完的部署。
// applying：进程在部署中途退出，恢复全部原文件并执行一次后置命令；平台已按结果未知处理，不再上报。
// finished：结果已得出但可能没送达，返回给调用方尝试补报。
func recoverJournal(store journalStore, run func(string) error) (*journal, error) {
	j, err := store.load()
	if err != nil || j == nil {
		return nil, err
	}
	if j.Phase == "finished" {
		return j, nil
	}

	paths := make([]string, 0, len(j.Backups))
	for _, b := range j.Backups {
		paths = append(paths, b.Path)
	}
	if unrestored := restore(j.Backups, paths); len(unrestored) > 0 {
		return nil, errors.New("restore failed for: " + strings.Join(unrestored, ", "))
	}
	if j.PostCommand != "" {
		if err := run(j.PostCommand); err != nil {
			return nil, errors.New("post command failed after restore: " + err.Error())
		}
	}
	return nil, store.remove()
}
