# 架构与开发

## 请求与权限

DSM CGI 硬链接调用 `synovpn` 桥，将真实 CGI 环境转发到套件账号的 Unix socket。浏览器伪造的内部桥头和 Forwarded 信息会被移除。门户调用 DSM authenticate.cgi 校验 Cookie/SynoToken，并查本地账号和组；不保存 DSM 密码。

Web → 固定 loopback 127.0.0.1:18447 → 容器引擎，使用独立令牌。容器使用 VICI 管理自己的 charon，Linux 内核处理 IPsec 数据。门户不访问 Docker socket，CA 与撤销账本保留在引擎命名卷。

普通 API 在逐次认证、同源/CSRF 校验后操作 owner 限定设备。管理员路由位于 `/api/admin/`，只允许元数据列表和解绑；SQL 元数据查询不读取私钥。管理员解绑和审计原子提交，后端成功后才确认 revoked。

二维码凭据只允许单设备单次领取，摘要存在内存，fragment 令牌打开后清除并通过同源 POST 领取。它不授予管理账号权限。

## 修改入口

- 页面与样式：`internal/web/ui.html`，通过 Go embed，修改后必须重新编译/重启。
- 个人、管理员、扫码 API：`internal/web/app.go`、`admin.go`、`enrollment.go`。
- DSM 认证/组权限：`internal/auth`。
- SQLite/审计：`internal/store`；当前 schema 2，管理员功能无迁移。
- Apple/Windows/Android 配置：`internal/profile`。
- 证书/CRL 与 IKE 身份：`internal/pki`、`internal/engine`。
- DSM 安装与容器资源：`packaging`。

## 验证顺序

1. `go test ./...`、`go vet ./...`，按改动补充权限、失败恢复、协议或数据一致性检查。
2. 使用 loopback demo 验证页面；它没有实际 VPN 连接，不把假 PKI 当真实凭据。
3. 引擎或编译参数变化时做 Docker 构建及 VICI 自检；仅门户变化可复用准确的 NAS 自检引擎。
4. 构建 SPK、检查哈希、包权限和许可证，部署到测试 NAS。
5. 实机验证 SSO、身份隔离、客户端导入、外网握手、内网/DNS 和解绑重连拒绝。分别记录模拟测试与实机结果。

当前检查共 48 个 Go 测试，数量随代码变化。详见 VALIDATION.md 与 docs/validation。

## 版本与发布

不要提交生产 SQLite、CA、设备 P12、私钥、会话令牌或用户配置文件。`var/`、`runtime/`、`build/`、`dist/` 默认被 Git 忽略；runtime 是本地交付的已验证运行时资料，可从源码重建。若分发包含运行时的归档，必须随附源码与许可证。

历史版本原始说明保存在 docs/history，仅供追溯，不作为当前部署步骤。构建输出描述仍标记为 preview/NAS validation required，这不替代已有实机记录，也不代表其他 NAS 自动兼容。
