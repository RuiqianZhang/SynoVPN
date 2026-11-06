#!/bin/sh
set -eu
mkdir -p /workspace/next
# Copy contents without trying to chown NAS-owned source files.
cp -r /src/. /workspace/next/
cd /workspace/next
go test -p 1 ./...
go vet ./...
python3 tools/build.py --target sa6400 --runtime /workspace/runtime/amd64 --smoke-local
cp dist/*.spk dist/*.sha256 /out/
