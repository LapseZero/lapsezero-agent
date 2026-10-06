#!/bin/sh
# 交叉编译 Linux 二进制，连同安装脚本和校验和输出到 dist/
set -eu
cd "$(dirname "$0")"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
rm -rf dist
mkdir -p dist
for ARCH in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "dist/lapsezero-agent-linux-$ARCH" .
done
cp install.sh dist/
cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum lapsezero-agent-linux-* > SHA256SUMS
else
  shasum -a 256 lapsezero-agent-linux-* > SHA256SUMS
fi
echo "built $VERSION into dist/"
