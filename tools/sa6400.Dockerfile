# syntax=docker/dockerfile:1
# Dedicated build image; no Docker socket and no NAS system tools are required.
FROM golang:1.27-alpine3.23
RUN apk add --no-cache build-base linux-headers openssl-dev openssl-libs-static zlib-dev zlib-static python3 file curl
WORKDIR /workspace
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
ENV GOMAXPROCS=2 GOMEMLIMIT=1300MiB GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
RUN go test -p 1 ./... && go vet ./...
COPY tools/compile-runtime.sh tools/disable-udp-gro.py tools/
RUN /bin/sh tools/compile-runtime.sh
COPY . .
RUN python3 tools/build.py --target sa6400 --binaries-only
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
ENTRYPOINT ["python3", "tools/build.py", "--target", "sa6400", "--runtime", "runtime/amd64", "--smoke-local"]
