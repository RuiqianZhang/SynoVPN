# SynoVPN

群晖 DSM 上的轻量 IKEv2 VPN 自助套件：Go、SQLite、strongSwan 证书认证、DSM 原生登录、手机扫码领取配置和管理员设备管理。

当前版本 **0.5.0-1**，已在 **SA6400 / DSM 7.4.1-90080 Update 1 / epyc7002** 安装运行。iPhone 移动数据连接和用户主动解绑已验证；管理员身份、全局设备列表及搜索筛选已实机验证。跨用户管理员解绑、不同客户端系统等验证边界见 [VALIDATION.md](VALIDATION.md)。这是开发预览版。

## 开始使用

- [构建与 SPK 打包](docs/BUILD.md)：Windows 快速打包、Docker 完整重编、NAS Container Manager 构建。
- [安装、升级与网络配置](docs/INSTALL.md)：安装向导、自动容器生命周期、端口、持久化和备份。
- [用户和管理员使用方法](docs/USAGE.md)：证书安装、扫码、解绑及管理入口。
- [排障](docs/TROUBLESHOOTING.md)、[架构与开发](docs/DEVELOPMENT.md)。
- [安全边界](SECURITY.md)、[第三方依赖](THIRD_PARTY.md)、[变更记录](CHANGELOG.md)。

## 本地运行

需要 Go 1.26+。在项目根目录运行：

```sh
go test ./...
go vet ./...
go run ./cmd/synovpn demo --data ./var/demo --listen 127.0.0.1:8787
```

浏览器访问 http://127.0.0.1:8787。演示只监听本机，使用假身份与隔离 PKI，不建立 VPN。演示账号有管理员视图，仅用于预览。生产入口必须通过 DSM 原生会话验证。

## 文件结构

| 目录 | 内容 |
|---|---|
| `cmd/synovpn` | CGI 桥、Web、生产引擎和本地演示入口 |
| `cmd/vici-probe` | 真实 strongSwan/VICI 签发和撤销自检 |
| `internal` | 认证、数据库、证书、配置生成、引擎、网络、Web 与测试 |
| `packaging` | DSM 生命周期、权限、安装向导、菜单、容器资源 |
| `tools` | 编译、静态引擎构建、GRO 兼容补丁及打包工具 |
| `vendor` | Go 依赖源码，可离线编译 |
| `runtime/amd64` | 已在 NAS 自检的静态 charon、上游源码归档与许可证 |
| `licenses` | 第三方许可证 |
| `dist` | 当前发行 SPK 和 SHA-256；重新构建的包也输出到这里 |
| `docs` | 构建、部署、操作、验证和历史资料 |

设备关联的是 DSM 用户与独立证书，不是不可复制的硬件绑定。VPN 使用证书，不使用群晖密码。Web SSO 只负责门户登录。普通用户只管理自己设备；管理员组成员有单独的全局列表和解绑入口，不提供他人的私钥下载。

`dist` 中随附的 SPK 是已经部署的发行包。重新打包会纳入当前文档等内容，SHA-256 可能改变，请使用同次构建生成的校验文件。
