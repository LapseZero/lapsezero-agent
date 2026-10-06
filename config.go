package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type config struct {
	Server     string `json:"server"`
	Credential string `json:"credential"`
}

func loadConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Server == "" || cfg.Credential == "" {
		return cfg, errors.New("config is missing server or credential, run enroll first")
	}
	return cfg, nil
}

// 凭证只在这里落盘，权限 0600
func saveConfig(path string, cfg config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
