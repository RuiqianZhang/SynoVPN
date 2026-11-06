# 0.5.0-1 NAS 管理员入口验收

2026-11-06，SA6400 / DSM 7.4.1-90080 Update 1。经用户确认已升级并启用管理员功能。套件中心显示安装版本 0.5.0-1、已启动、存储空间 3。

当前 zhangruiqian 会话通过 DSM 管理员组校验，出现“我的设备 / 管理员 · 设备管理”切换入口。实机全局列表显示 4 条设备记录及用户名归属，网关就绪。按“我的iPhone”搜索返回 1 条，筛选仅在线返回 0 条；结束时恢复全部设备视图。

当前 4 条记录均已解绑，故有效设备、在线设备及有有效设备的用户均为 0。本次升级未创建凭据、未重新签发证书、未执行设备解绑，保留原有记录。

普通用户越权、角色撤销、跨用户解绑、票据作废、审计回滚及后端故障重试通过自动化测试；本次未新增非管理员 DSM 实机账号，也未对真实在线设备执行管理员跨用户解绑，不能把这两项记为实机通过。

升级前 48 项 Go 测试、go vet、本机隔离界面验收通过。SPK SHA-256：60641d1d70dc654336e381383195bd58df78995492df52ca7f80bb57aa59a967。


# SynoVPN 0.5.0-1：管理员设备管理（已更新 NAS）

DSM 本地 administrators 组成员登录后会出现“管理员 · 设备管理”入口。保留现有允许使用套件的用户组检查（当前为 users）。管理员身份每次请求都由本机用户组重新判定，不能用用户名、URL 或浏览器参数伪造。

管理员可查看全部用户的设备名称、用户名、系统、创建/到期时间、状态及在线标记，按用户名或设备搜索并筛选在线/未解绑/已解绑设备。可确认后解绑任何设备，撤销证书并按既有引擎流程清理会话。管理页不提供他人的证书私钥下载或扫码签发。

普通用户只有个人设备视图，后端继续校验设备 owner。管理员的个人视图和原有下载接口同样不允许访问他人的配置。全局管理采用独立路由，普通用户直接调用也返回拒绝。

管理员解绑和审计记录在同一 SQLite 事务提交：audit.actor 为管理员的 DSM UID/用户名，action 为 admin-revoke，device 为目标设备 ID，at 为操作时间；通过保留的设备记录可查询目标用户。审计写入失败会回滚解绑。引擎故障时保留 revoking 并返回 202，恢复后重试；不提前宣称撤销和断连成功。所有该设备的未使用二维码及下载票据会失效。

验证：48 项 Go 测试、go vet、前端语法检查通过。覆盖普通用户越权、管理员降权后拒绝、CSRF/登录/跨站/内网来源校验、元数据不读取私钥、下载权限不扩大、选择性撤销、票据失效、审计失败回滚和故障重试。本机隔离演示还验证了管理员导航、两位用户的归属、搜索、在线/有效状态筛选、解绑确认及落库审计。

NAS 尚未安装该版本；DSM administrators 实机识别、全局管理页面、跨用户解绑需升级后验收。现有 0.4.0-4 不受本次本地开发影响。用户已确认此前 iPhone 解绑由本人操作且确实有效。

现有设备/证书保留，无数据库 schema 变更；继续使用已验证的静态 charon（含 DSM UDP GRO 兼容补丁）。

# 0.4.0-4：在线状态诊断与验收

2026-11-06：用户报告手机已连接但门户显示未连接。服务器保活和 IKE/CHILD_SA 日志确认隧道存在。新增仅在会话状态变化时记录的引擎诊断，包含会话数量、公开证书身份映射和状态，不记录私钥、会话密钥或 DSM 令牌。

更新并由用户重新连接后，VICI 显示 sessions=1、allowed=1、ESTABLISHED，证书 DNS 身份正确匹配，门户刷新后显示 1 台在线。之前不一致的具体根因尚未确定，不把增加日志或重启描述为已定位的代码修复。

设备归属采用 DSM 本地 UID + 用户名；列表和设备操作按 owner 查询。没有普通用户跨账号总览功能。管理员的系统级权限不受此应用隔离约束；证书配置可以复制，设备绑定不是硬件锁定。

42 项 Go 测试以及 go vet 通过（新增 Apple FQDN 会话识别/选择性撤销、在线状态用户隔离回归检查）。在线解绑的新增测试为自动化模拟检查，不视为真实手机在线断连验收。

# 0.4.0-3：内网 DSM 地址管理修复

已登录 DSM 的管理 API 支持原生 CGI 所服务的精确同源地址，包括 https://192.168.10.10:5001。内网会话的 CSRF 令牌绑定地址、用户和会话；跨站、缺少令牌、换用户、换地址仍拒绝。忽略浏览器转发来源头，二维码仍使用管理员固定的公网 HTTPS 地址。

前端检查响应类型与重定向，DSM 登录页、403 错误页或无效 JSON 不再直接显示 Unexpected token。40 项 Go 测试、go vet、前端语法及 HTML/重定向/无效 JSON 检查通过。保留 0.4.0-2 的 UDP GRO 兼容性补丁。

# 0.4.0-2：DSM UDP GRO 兼容性修复（待实机拨号复验）

11:38–11:41 日志发现 IKE_AUTH 分片合并后完整性校验失败。strongSwan 6.1.0 默认设置 UDP_GRO，DSM 5.10.55+ 内核表现与上游报告一致。仅移除 VPN 引擎设置该 socket 选项的操作，保留 UDP_ENCAP、加密和证书校验；不改宿主网卡 GRO。

固定上游源码归档校验后使用 tools/disable-udp-gro.py 应用可审阅补丁。修复引擎已在 NAS 隔离构建容器通过真实 VICI、证书签发及 CRL 撤销自检。引擎 SHA-256：4c275a7ef2826eed2465e0cbd256489d394582ea3c2f88b7a1db0e28fa1cf4c4。手机拨号仍待更新后复验。

参考：https://github.com/strongswan/strongswan/discussions/3064

# 0.4.0-1：手机扫码领取（已更新 NAS，手机验收待完成）

新增 iPhone / iPad、Android 设备的“手机扫码安装”按钮。二维码本地生成，领取链接有效 5 分钟且仅可下载一次；手机无需登录 DSM。二维码持有人可领取该设备的证书与私钥，请勿转发。重新生成、关闭作废、到期、解绑或服务重启均使旧链接失效。

iPhone / iPad 请用 Safari 领取 mobileconfig，再在设置 → 通用 → VPN 与设备管理中确认安装。Android 领取 ZIP 后按说明导入证书并配置 IKEv2/IPSec RSA，系统支持依版本和厂商而异。扫码不代替系统授权，也不会自动拨号。

外网需转发 UDP 500、UDP 4500 到 NAS 同号端口；外网扫码领取还需现有 HTTPS TCP 888。NAS 防火墙也需放行。当前强制 ESP-in-UDP，不需另转发 ESP 或 UDP 1701；不要公开引擎控制端口 18447。HTTPS 反向代理不能代替 VPN 的 UDP 转发。

37 项 Go 测试及 go vet、二维码独立解码、本机浏览器单次下载和重复领取拒绝检查通过。2026-11-06 已更新 NAS，用户识别、网关就绪、二维码生成及临时设备撤销通过；浏览器触发配置下载但报告取消，真实手机领取、安装和拨号仍待验收。下面的 0.3.0-10 为既有实机记录。

# 当前实机状态：0.3.0-10

2026-11-05：SA6400 / DSM 7.4.1-90080 Update 1 已安装并启动。DSM 会话识别、网关就绪、套件启停和 Windows 测试证书的签发、下载、撤销通过。真实客户端隧道、在线解绑断连和跨系统兼容性仍待验收。详见 VALIDATION.md。

门户的空白界面可在未认证时加载；所有设备、账号、配置和下载 API 均需原生 DSM 会话校验。页面从同源 DSM 启动窗口取得 SynoToken，仅在页面内存中使用，通过请求头传递；原生进程将 Cookie、原始客户端地址及令牌交给 authenticate.cgi 验证。不保存 DSM 密码或会话令牌。

# SynoVPN 0.3.0：群晖 VPN 自助套件首版

用户从 DSM 主菜单打开套件，复用当前 DSM 会话；创建属于自己的设备，下载原生 IKEv2 配置，解绑时撤销该设备凭据并清理连接。首版不包含微信、不需要本机助手。

**交付状态：0.3.0 改为普通套件账号门户 + Container Manager VPN 引擎，正在验证。旧 0.2.0-1 因 root 声明被 DSM 拒绝，不可使用。新包不声明原生 root 权限，但引擎容器仍需要经管理员批准的宿主网络管理权限。**

## 从 0.1.0 升级

先停止套件，并完整备份 `etc/` 和 `var/`。数据库自动迁移到 schema 2：旧口令设备全部进入解绑流程、旧口令密文被清除，用户需要新创建设备并重新安装证书配置。原有服务器证书和用户审计记录保留，不会将旧密码转换为证书。

客户端 CA 使用 root 私有的 `client-ca.pem` / `client-ca.key`，签发/撤销状态持久保存在 `client-ledger.json`，CRL 为 `client-crl.der`。首次快照完成之前网关不加载接入连接，避免启动时暂时放行旧证书。账本丢失会拒绝启动；不能只恢复 CA 私钥而重建一个空账本，否则可能丢失撤销历史。

Windows 每个 NAS/客户端 CA 暂只允许安装一张未到期的设备证书，导入脚本遇到冲突会停止，避免系统选错证书。更换设备配置前，先在门户解绑旧设备，再由管理员手动移除旧客户端证书；脚本不会自动删除证书。

## 已实现

- Go 单一程序，区分 CGI 桥、普通套件账号 Web 服务和容器内 VPN 引擎；SQLite 使用 WAL。
- 使用 DSM 官方 `authenticate.cgi` 验证每一次请求。拒绝客户端伪造用户名；无本地登录回退。
- 群晖本地用户及允许用户组检查。首版不承诺 LDAP/AD 账号支持。
- 设备属于已验证的 `DSM UID + 用户名`，普通用户不能查看、下载或撤销其他用户的配置。
- 默认每用户最多 5 台有效/解绑中的设备，凭据 90 天到期。
- 一设备一 RSA 私钥和客户端证书，使用 IKEv2 双向证书认证；VPN 连接不使用账号密码，也不读取或复用 DSM 密码。
- 设备私钥在 SQLite 中使用 AES-GCM 加密，设备 ID 作为附加认证数据；加密密钥文件独立且权限为 0600。证书序列号及公开证书另行保存。
- Apple `.mobileconfig` 内含 PKCS#12 设备身份；Windows/Android ZIP 内含设备 P12、两个公开 CA、证书元数据和指引。Windows 使用一次性配置脚本。
- 下载需先 POST 申请 60 秒单次票据，绑定当前用户及会话。解绑会令已签发下载票据失效。
- 解绑先持久化为 `revoking`，在 root 私有账本永久撤销设备、签发并加载 CRL，清理验证缓存，再按证书身份对应的 IKE SA ID 断连并复查；成功后才标记 `revoked` 并清除私钥密文。未完成签发的设备也会留下永久撤销记录，阻止迟到请求重新签发。
- 同步失败每 5 秒重试；root 进程独立每 2 秒处理到期及撤销后迟到的 SA。CRL 每 24 小时有效、剩余不足 6 小时自动重签；strict 策略拒绝缺少有效撤销证明的客户端。解绑优先于新证书签发，单个签发故障不会阻塞其他设备解绑。
- IKEv2/IPv4 内网分流、明确的访问网段、内网 SNAT；独立的 iptables 链及 reqid。

设备绑定指独立证书与账号的关联，不是不可复制的硬件锁定。下载文件含私钥，应妥善保存，安装后删除下载副本。首次导入可能需要本机密码或 P12 导入密码；这不是 VPN 登录密码，后续连接不需要账号密码。

## 预览

已编译的 Windows 预览程序可运行：

```powershell
.\build\synovpn-demo.exe demo --data .\var\demo --listen 127.0.0.1:8787
```

打开 `http://127.0.0.1:8787`。页面明确标记“本地演示”；此模式使用隔离的模拟认证/引擎，**不监听 IKE 端口、不建立 VPN**，下载文件只供检查格式。

也可用 Go 1.26 或更新版本运行 `go run ./cmd/synovpn demo`。演示入口只能绑定本机回环地址。生产 `run/web` 命令不能启用演示认证。

## 当前指定的 SA6400 目标

用户目标为 SA6400 / DSM 7.4.1-90080 Update 1，软件编译为 Linux amd64，套件平台为 epyc7002。指定构建使用 `python3 tools/build.py --target sa6400 --build-runtime --smoke`；NAS Container Manager 隔离构建方案见 [SA6400.md](SA6400.md)。平台匹配不等于已经通过 DSM 实机验收。

## 构建完整 SPK

在有 Go 1.26+、Python 3、Docker BuildKit 的 Linux/开发机器上：

```sh
go test ./...
go vet ./...
python3 tools/build.py --arch amd64 --build-runtime --smoke
# ARM64 构建建议在原生 ARM64 Linux/Docker 上运行：
python3 tools/build.py --arch arm64 --build-runtime --smoke
```

输出为 `dist/SynoVPN-0.3.0-amd64.spk` 或 `dist/SynoVPN-0.3.0-arm64.spk` 及 SHA-256 校验文件。

打包工具检查 Go 程序与 charon 的 ELF 架构，拒绝具有动态解释器依赖的运行程序，缺少 charon 时拒绝生成 SPK。strongSwan 固定为 6.1.0，源码下载校验 SHA-256；Docker 构建静态 musl/OpenSSL 版本，避免依赖 NAS 的 glibc 或额外 VPN 包。构建同时打包 strongSwan 源码及许可证。

`--smoke` 在带 NET_ADMIN/NET_RAW 能力的容器内启动实际 charon，检查 VICI、服务器证书和私钥、证书认证连接/地址池、设备签发及 CRL 撤销。这仍不等价于 Windows/Apple/Android 实机互通。

仓库包含 `.github/workflows/build.yml`，用于在 x86_64、ARM64 Linux runner 上构建及上传包。**本次没有创建远程仓库、推送代码或运行该工作流。**

仅交叉编译管理程序、不创建安装包：

```sh
python3 tools/build.py --arch amd64 --binaries-only
```

## NAS 安装

目标范围：DSM 7.2+。x86_64 为首个验证目标；ARM64 的包元数据暂限定 `rtd1296/rtd1619b`。元数据不是通过实机验证的承诺；其他机型/架构需要另行验证。

1. 使用独立测试 NAS 或备份后的测试环境。确认内核支持 XFRM/IPsec、iptables policy/conntrack/MASQUERADE。不要同时运行占用 UDP 500/4500 的 VPN Server 或其他 IPsec 服务。
2. 为 VPN 准备域名；如通过路由器访问，转发 UDP 500/4500 到 NAS。QuickConnect 不能替代 IKEv2 的网络入口。
3. 在 DSM 套件中心手动安装构建后的 SPK，填写公网 VPN 域名、规范的 DSM HTTPS 地址（例如 `https://nas.example.com:5001`）、允许的内网网段、DNS、地址池及用户组。
4. 如果系统未启用 IPv4 转发，选择安装向导中的启用选项，或由管理员事先启用。转发是共享系统设置，停止/卸载套件不会自动改回 0。
5. 登录 DSM，从主菜单打开 SynoVPN。当前 DSM 身份必须属于允许用户组。通过其他域名访问 DSM 可能导致 Origin 校验失败，请使用安装时填写的规范地址。
6. 每台设备分别创建配置、下载并安装，然后从系统 VPN 开关连接。

初次启动会创建专用 VPN CA/服务器证书。客户端下载需要信任这一 CA；Apple 描述文件未进行 CMS 签名，系统会显示相应安装提示。不要关闭 DSM 自身的 CSRF 或证书校验来解决接入问题。

### 各平台首次配置

| 平台 | 下载内容 | 用户操作 |
| --- | --- | --- |
| iPhone/iPad | `.mobileconfig`，含服务器 CA、设备证书和私钥 | 使用 Safari 下载，进入设置安装，再连接 |
| macOS | `.mobileconfig` | 打开并在系统设置批准安装，再连接 |
| Windows | ZIP：两个 CA、P12、证书元数据、一次性 PowerShell 配置脚本 | 解压，以管理员权限运行脚本并核对 CA 指纹，随后直接在系统设置连接 |
| Android | ZIP：CA、P12、导入密码和指引 | 在支持 IKEv2/IPSec RSA 的系统中导入证书并手工配置；不同厂商入口不同 |

Windows 脚本不更改全局执行策略；如果执行策略阻止，应按组织策略处理，或手动配置。没有注册自定义协议，没有安装常驻本机助手，没有承诺网页自动连接。

## 结构与数据

DSM 浏览器通过 app.cgi 访问本机普通套件账号运行的 Web 服务；Web 服务逐次调用 DSM authenticate.cgi，按 DSM 用户隔离 SQLite 设备记录。门户不具有 root、Linux 网络能力或 Docker socket 访问权。

ContainerManager>=1432 通过官方 docker-project resource worker 管理 VPN 引擎。容器使用 host 网络和 DAC_OVERRIDE、NET_ADMIN、NET_RAW、NET_BIND_SERVICE；不使用 privileged，不挂载宿主根目录。引擎仅监听 127.0.0.1:18447，所有控制请求需独立随机令牌；不发布 LAN TCP 管理端口。256 MB 是引擎容器内存上限，不是已测得的常驻内存。

- 本机配置：`/var/packages/SynoVPN/etc/config.json`，套件账号拥有；引擎仅在首次启动导入并固定允许的域名、地址池、网段和 DNS。
- 本机令牌：`/var/packages/SynoVPN/etc/engine.token`，32 字节，0600，不交给 CGI/http 用户。
- 引擎私有数据：Docker 命名卷 `synovpn-engine-state` 中的 `/var/lib/synovpn-engine/`，保存 root 私有 CA、撤销账本、固定配置和令牌。配置或令牌恢复需管理员显式处理，不自动重新初始化已有 CA。
- SQLite、设备私钥密文与公开 CA 副本：`/var/packages/SynoVPN/var/web/`，套件账号 0700。
- Web Unix socket 允许 DSM CGI 连接，但全部应用请求仍验证 DSM 会话；该 socket 不提供未鉴权的引擎操作。
- Web 日志：`/var/packages/SynoVPN/var/log/synovpn.log`；引擎日志在 Container Manager。日志不记录令牌、Cookie、SynoToken、私钥或下载票据。

引擎失败会停止 charon；资源管理器负责随套件启动和停止引擎。引擎仅维护 SVPN_INPUT、SVPN_FORWARD、SVPN_NAT 专属防火墙链与固定跳转，不清空 DSM 规则。IPsec reqid=43177 策略限制允许的流量。默认不启用宿主 IPv4 转发，NAS 必须已启用这一设置；容器不会尝试放宽只读 proc 限制。

首次安装需联网拉取 Alpine 3.23 并安装 iptables/iproute2。运行时无 Go SDK。备份必须同时保存本机配置、令牌、SQLite 与其加密密钥，以及引擎命名卷的 CA/账本。命名卷和套件数据的升级/卸载保留行为尚待实机验证，不应在没有备份时卸载。

## 已知边界与下一次 NAS 验收

- 0.3.0 必须重新验收 DSM 安装、资源 worker、CGI 权限、引擎启动/停止与真实客户端连接。旧版真实 VICI 通过不替代新版整体部署验证。
- 0.2.0 原生 root 运行布局不支持直接原地升级到本布局；该版本在用户设备上尚未成功安装。
- Windows/macOS/iOS/Android 的证书信任、分流、DNS、重连与撤销拒绝行为仍需实测。
- 首版无微信、IPv6、全局代理、逐应用 VPN、MDM 或证书自动续期界面。
- 停用 DSM 用户不会自动撤销已发证书；管理员需先解绑其设备。
- 默认每人 5 台设备、90 天证书，最多同步 4096 台设备。

见 VALIDATION.md 了解已执行检查，见 SECURITY.md 了解认证与权限边界。

## 参考文档

- [DSM Application Authentication](https://help.synology.com/developer-guide/integrate_dsm/web_authentication.html)
- [DSM Desktop Application](https://help.synology.com/developer-guide/integrate_dsm/desktopapp.html)
- [DSM Privilege Config](https://help.synology.com/developer-guide/privilege/privilege_config.html)
- [strongSwan certificate configuration](https://docs.strongswan.org/docs/latest/interop/windowsCertServerConf.html)
- [strongSwan VICI protocol](https://github.com/strongswan/strongswan/blob/6.1.0/src/libcharon/plugins/vici/README.md)
