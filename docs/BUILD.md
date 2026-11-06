# 构建与 SPK 打包

所有命令均在项目根目录执行。Go 1.26+（已验证 Go 1.27.3）、Python 3.10+。Go 依赖已放在 vendor 中，不需要额外数据库服务或 Node.js 来构建产品。

## 1. 测试和本地演示

```sh
go test ./...
go vet ./...
go run ./cmd/synovpn demo --data ./var/demo --listen 127.0.0.1:8787
```

演示管理员只在 loopback 隔离模式存在。退出用 Ctrl+C。演示数据只写到 `var/demo`，不能用作生产 VPN 配置。

## 2. Windows / Linux 快速打包（无需 Docker）

源码目录已随附准确的 NAS 自检引擎 `runtime/amd64/charon`。其 SHA-256 固定为：

```
4c275a7ef2826eed2465e0cbd256489d394582ea3c2f88b7a1db0e28fa1cf4c4
```

```sh
python tools/build.py --target sa6400 --runtime runtime/amd64 --reuse-verified-runtime
```

Go 不在 PATH 时：

```powershell
python tools/build.py --target sa6400 --runtime runtime/amd64 --reuse-verified-runtime --go "C:/path/to/go/bin/go.exe"
```

输出 `dist/SynoVPN-0.5.0-1-sa6400-epyc7002.spk` 及 `.spk.sha256`。构建会重新编译 Linux amd64 Go 程序、检查静态 ELF/目标平台和引擎哈希、打包 CGI 硬链接/资源/许可证。它不会安装到 NAS，也不会重跑真实引擎自检，不能将复用模式当作修改引擎后的验证。

PowerShell 校验发行包：

```powershell
Get-FileHash dist/SynoVPN-0.5.0-1-sa6400-epyc7002.spk -Algorithm SHA256
Get-Content dist/SynoVPN-0.5.0-1-sa6400-epyc7002.spk.sha256
```

不要手工修改准入哈希来绕过验证。修改 charon、编译参数或补丁后使用下一节的完整构建及真实引擎检查。

## 3. Docker 完整重编与真实引擎自检

需要 Linux 容器 Docker/BuildKit，能访问官方 Go/Alpine 镜像和 download.strongswan.org。构建中核对 strongSwan 6.1.0 归档哈希，并应用 `tools/disable-udp-gro.py`。该补丁仅禁用 VPN socket 的 UDP GRO，保留 NAT-T、加密与证书检查，兼容 DSM 旧内核。

```sh
python tools/build.py --target sa6400 --build-runtime --smoke
```

自检容器需要 NET_ADMIN、NET_RAW，在自己的网络命名空间运行，不使用 host 网络、不挂载 Docker socket。`--smoke` 失败时不会生成目标 SPK。自检覆盖 VICI、证书签发/CRL、连接配置，不替代真实手机握手测试。

其他架构只用于开发，未通过本型号实机验收：

```sh
python tools/build.py --arch arm64 --build-runtime --smoke
```

建议 ARM64 在原生 ARM64 Linux/Docker 构建，不能把它装到 SA6400。

## 4. 在 NAS / Linux 主机的 Compose 构建

将整个项目目录放到健康存储空间的独立目录，例如 `/volume3/docker/synovpn-build`，并创建 `dist` 子目录。`compose.sa6400.yml` 直接以项目根目录为 context，不需要额外套 `source` 文件夹。

```sh
mkdir -p dist
docker compose -f compose.sa6400.yml build
docker compose -f compose.sa6400.yml up --abort-on-container-exit --exit-code-from synovpn-builder
```

在 Container Manager 图形界面创建项目时，选择该文件并构建、启动；检查容器日志包含真实 VICI 验证通过和 SPK 输出路径。输出在宿主项目目录的 `dist`。下载 SPK 与 SHA-256 后核对并手动安装。构建项目本身不会安装或启动生产 VPN。

构建容器只写自身层和 `dist`，运行阶段无网络，2 GB 内存、CPU 0/1。不要给它 host 网络、Docker socket 或证书数据卷。SA6400 曾不支持 PIDs/NanoCPU 限制，Compose 不依赖这些参数。Docker 基础镜像构建阶段仍需要联网。

清理自己的构建项目（在该项目目录执行）：

```sh
docker compose -f compose.sa6400.yml down
```

不要对生产引擎执行 `down -v`，也不要运行全局 prune。删除构建镜像会丢失构建缓存，但不应删除生产卷。

## 5. 发版修改点

当前版本号位于 `tools/build.py` 的 INFO 与 SPK 文件名，以及 `packaging/engine/compose.yaml` 的镜像标签。发版时同步修改这三处，并更新 CHANGELOG / 验证记录。运行测试、构建、自检并核对产物。CI 配置在 `.github/workflows`，需要受支持的 Linux runner 和 Docker；本次未执行远程 CI 或从空缓存重跑 Docker 全量构建。
