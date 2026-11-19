# sb-manager alpha.34 运维接入

`/operations` 的“目标服务器运维”支持本机和远程 Agent。服务器详情页提供带目标参数的入口；下方“其他本机工具”仍明确只操作控制端本机。

| 功能 | 上游要求 |
| --- | --- |
| TCP 缓冲区预览/应用/恢复、网络 ping | alpha.31+ |
| iperf3 测速/历史/对比、SOCKS5/HTTP/mixed、节点期限、共享配额、tc 整形 | alpha.32+ |
| 本地托管 Tunnel 与域名/路径路由、Sub-Store 生命周期及组件备份 | alpha.32+ |
| Sub-Store 动态来源同步、远程来源、自动组合、live/never 订阅及按 ID 撤销 | alpha.34+ |

远端须升级到支持 `operations_v2` 的本项目 Agent。本机在提交时读取实际 `sb version`，远端使用最近心跳版本。版本过旧、离线或 Agent 不支持时拒绝提交，不让未知命令进入目标。

## 接口

`GET /api/v1/operations` 返回固定操作和字段清单。`POST /api/v1/operations` 接受：

```json
{"server_id":"local","action":"tcp.plan","args":{"bandwidth":500,"rtt":100},"idempotency_key":"独立请求标识"}
```

返回现有任务对象，通过 `GET /api/v1/tasks/{id}` 查看。viewer 可通过此接口提交只读查询；所有 POST 仍要求 Session 和 CSRF。组件安装、manager 更新、Tunnel 凭据配置和私有订阅操作只允许 admin。旧 action/batch 路径使用相同的权限与兼容性检查。

## 私有结果

订阅创建、Sub-Store 来源 URL 和私有访问地址通过加密任务传递。参数与结果使用 AES-GCM 加密存储于 SQLite `task_secrets`，不进入普通 task JSON、任务列表或审计。Agent 只通过已验证的控制端连接收到本机任务参数。

管理员通过 `POST /api/v1/tasks/{id}/private-result` 领取一次结果，15 分钟后不再提供。查看原始结果只写审计事件，不记录其内容。页面不会将其保存到 localStorage。结果丢失时，访问地址可重新查询；动态订阅应按 ID 撤销后重新创建。

加密密钥为 `<database>.secrets.key`（0600）。在线数据库备份同时生成 `<backup>.secrets.key`，两者必须一起保护、一起恢复。只有数据库没有密钥时，已有私有任务不能恢复；程序拒绝用新密钥替代它。

中断的新版修改操作可能已经作用于目标，控制端重启后标记失败并要求核查，不自动重放“延长 N 天”等非幂等命令。明确失败或取消的任务仍可由有权限用户手动重试。

## 目标机文件

本地托管 Tunnel：先在目标机按 Cloudflared 官方流程取得凭据，将 JSON 存在 `/etc/sb-manager/secrets/`，Web 仅提交文件名和 Tunnel UUID。这里不上传云端账号密钥、不自动配置 DNS。

Sub-Store 独立备份：限定在目标机 `/var/lib/sb-manager/substore-backups/名称.tar.gz`。完整 sb-manager 备份也包含 Sub-Store 数据。备份和恢复都由上游处理服务状态、检查及回滚。

共享节点额度、网卡整形和客户商业套餐属于不同层面。商业用户继续由 Marzban 管理，不能将这里的节点端口配额作为客户账本。

## 验证

```bash
go test ./...
go vet ./...
SB_MANAGER_SOURCE=/root/proj/sbmanager go test ./internal/runner -run TestUpstreamOperationsContract -count=1
bash tests/install-smoke.sh
```

真实上游 CLI 合约测试只使用 sb-manager 自带隔离 fixture，不安装系统服务或修改宿主机代理状态。远程 VPS、生产防火墙与真实链路吞吐另行验收。
