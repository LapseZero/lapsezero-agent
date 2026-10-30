#!/bin/sh
# 交叉编译 Linux 和 Windows 二进制，连同校验和及其签名、两个平台的安装脚本输出到 dist/
set -eu
cd "$(dirname "$0")"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
SIGNING_KEY=${SIGNING_KEY:-$HOME/.config/lapsezero/agent-signing.key}
[ -f "$SIGNING_KEY" ] || { echo "signing key not found: $SIGNING_KEY" >&2; exit 1; }
rm -rf dist
mkdir -p dist
for ARCH in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "dist/lapsezero-agent-linux-$ARCH" .
done
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" \
  -o "dist/lapsezero-agent-windows-amd64.exe" .
cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum lapsezero-agent-linux-* lapsezero-agent-windows-*.exe > SHA256SUMS
else
  shasum -a 256 lapsezero-agent-linux-* lapsezero-agent-windows-*.exe > SHA256SUMS
fi
# 客户端自动更新只接受带签名的 SHA256SUMS
(cd .. && go run ./tools/sign sign "$SIGNING_KEY" dist/SHA256SUMS) > SHA256SUMS.sig
# 两个平台的 Release 各上传一份 install.sh，默认从所在平台下载二进制，安装命令就不必再传 --release
for PLATFORM in github:https://github.com/LapseZero gitee:https://gitee.com/lapsezero; do
  mkdir -p "${PLATFORM%%:*}"
  sed "s|^RELEASE=\"\"$|RELEASE=\"${PLATFORM#*:}/lapsezero-agent/releases/download/$VERSION\"|" \
    ../install.sh > "${PLATFORM%%:*}/install.sh"
done
echo "built $VERSION into dist/"
