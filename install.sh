#!/bin/sh
# 安装 lapsezero-agent：下载并校验二进制、注册本机、写入 systemd 服务并启动。
# 用法：curl -fsSL <Release 地址>/install.sh | sh -s -- --server <站点> --token <注册码>
# <Release 地址> 是 GitHub 或 Gitee 上某个 Release 的附件下载前缀，例如
# https://github.com/<owner>/lapsezero-agent/releases/download/<tag>
# build.sh 会把所在 Release 的地址写进 RELEASE 默认值；直接运行源码版本时需要传 --release。
set -eu

RELEASE=""
SERVER=""
TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release) RELEASE="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

fail() { echo "Error: $*" >&2; exit 1; }

[ -n "$RELEASE" ] && [ -n "$SERVER" ] && [ -n "$TOKEN" ] || fail "--release, --server and --token are required"
# 不在命令里写 sudo：root 用户的系统可能没装 sudo，非 root 时才需要它
SUDO=""
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail "please run as root, or install sudo"
  SUDO="sudo"
fi
[ "$(uname -s)" = Linux ] || fail "only Linux is supported"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

BINARY="lapsezero-agent-linux-$ARCH"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $BINARY..."
fetch "$RELEASE/$BINARY" "$TMP/$BINARY"
fetch "$RELEASE/SHA256SUMS" "$TMP/SHA256SUMS"
EXPECTED=$(grep " $BINARY\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$(sha256 "$TMP/$BINARY")" ] || fail "checksum mismatch"

$SUDO install -m 0755 "$TMP/$BINARY" /usr/local/bin/lapsezero-agent
$SUDO /usr/local/bin/lapsezero-agent enroll --server "$SERVER" --token "$TOKEN"

$SUDO tee /etc/systemd/system/lapsezero-agent.service >/dev/null <<'UNIT'
[Unit]
Description=LapseZero deploy agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/lapsezero-agent run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

$SUDO systemctl daemon-reload
$SUDO systemctl enable lapsezero-agent >/dev/null 2>&1
$SUDO systemctl restart lapsezero-agent
echo "lapsezero-agent is installed and running. Check it with: systemctl status lapsezero-agent"
