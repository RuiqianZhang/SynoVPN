# DSM 7 安装阻断与修复边界

2026-11-03：用户实机安装 0.2.0-1，被 DSM 提示“由于 SynoVPN 以 root 权限运行，因此无法安装”。旧 SPK 不可安装使用。

## 已确认的根因

- conf/privilege 的 defaults 和控制脚本均声明 run-as=root。
- 现有 init 要求 root，supervise 也要求 root，并负责所有权设置、启动 charon、iptables 和降权启动 Web 子进程。因此直接把 privilege 改为 package 会导致安装或服务启动失败。
- Synology 官方 DSM 7 规则要求第三方套件降权；特权操作通过 resource worker 申请。普通第三方原生 root 套件需要厂商支持的开发/签发路径，不能假设用户能取得该资格。
- 另发现正式 charon 配置仍使用 4 个线程，与已修复的容器检查配置不一致；本轮源代码修正为 16。该修改尚未进入旧 SPK，也不解决 root 安装限制。

## 推荐的修复方案（待确认运行依赖）

1. SPK 的安装、启动、停止脚本和 DSM 门户均使用 SynoVPN 普通套件账号；移除所有 root 声明。
2. 保留 DSM 本机 authenticate.cgi 认证与用户隔离，SQLite、设备配置导出由本机 Web 进程处理。
3. 通过官方 docker-project resource worker 管理独立 VPN 引擎容器，声明 ContainerManager>=20.10.23-1432 为运行依赖；不授予门户 Docker socket 访问权。
4. 引擎使用独立持久卷保存 CA 私钥和撤销账本，只暴露经过鉴权的本机控制接口，向门户提供公有 CA、签发与撤销结果。
5. 引擎接入宿主网络，按需申请 NET_ADMIN、NET_RAW、NET_BIND_SERVICE；不使用 privileged，不挂载宿主根目录。这些权限会影响 NAS 网络，必须在实际安装/启动前展示并确认。
6. 安装生命周期交给资源管理器，明确升级保留 PKI/SQLite、卸载后的数据保留策略，重新执行 DSM 安装、启动/停止和真实客户端证书连接验收。

这会把 Container Manager 从“构建工具”变成“运行依赖”。若坚持纯原生、不依赖 Container Manager，则需要重新研究厂商支持的能力/资源路径或申请 Synology 授权；不能保证可直接侧载。

## 官方依据

- https://help.synology.com/developer-guide/breaking_changes.html
- https://help.synology.com/developer-guide/privilege/preface.html
- https://help.synology.com/developer-guide/getting_started/system_requirement.html
- https://help.synology.com/developer-guide/resource_acquisition/docker-project.html

## 当前状态

用户已接受 Container Manager 运行依赖。普通套件账号门户及受控引擎容器已实现并生成 0.3.0-2 SPK；29 项测试、vet 与隔离环境的实际 VICI 检查通过。DSM 安装、宿主网络运行和客户端隧道仍待验收，不能将旧包校验通过等同于新版部署完成。
