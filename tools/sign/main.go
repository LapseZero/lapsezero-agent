// sign 给 Release 的 SHA256SUMS 签名，客户端自动更新时用编译进去的公钥验证。
// 私钥只在发布者本机，不进仓库。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "genkey" {
		return genkey(args[1])
	}
	if len(args) == 3 && args[0] == "sign" {
		return sign(args[1], args[2])
	}
	return errors.New(`Usage:
  go run ./tools/sign genkey <private-key-path>   # prints the public key to embed in update.go
  go run ./tools/sign sign <private-key-path> <file>   # prints the base64 signature`)
}

func genkey(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// O_EXCL：不覆盖已有私钥，覆盖后已安装的客户端将不再接受新版本
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(keyPath, file string) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("invalid private key file")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)))
	return nil
}
