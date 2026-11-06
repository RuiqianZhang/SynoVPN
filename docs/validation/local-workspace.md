# 本地迁移与构建核验

2026-11-06。源码整理至 C:/Users/ruiqi/Codes/My/SynoVPN。

- cmd、internal、vendor、licenses、packaging、runtime、CI 文件与原工作目录逐文件 SHA-256 比对一致。
- README 与 docs 中的当前文档相对链接检查通过；历史说明移入 docs/history。
- 48 项 Go 测试及 go vet 在新目录通过。
- 静态 ELF 检查通过，接受 static PIE；Docker runtime recipe 同步使用该检查。
- 快速打包在新目录成功，权限为普通套件账号，CGI 硬链接与引擎哈希检查通过。
- 当前 SPK SHA-256：43dd0db6d47b7a7a88455a9461b27809e90d9909e796c5aefe02ec33605fc7ad。同名 .sha256 与产物一致。新文档纳入包内，因此与此前 NAS 已安装发行包的哈希不同。此次未更新 NAS。
- 本机未执行 Docker 完整重编或远程 CI；Compose 根目录与 Dockerfile 静态检查不能替代真实构建。
- 当前 Go 工具链使用既有工作环境，未修改系统 PATH 或安装新工具。独立开发需自行准备 Go 1.26+、Python 3，或使用文档中的 Docker 构建方式。
