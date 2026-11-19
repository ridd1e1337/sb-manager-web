# SNTP 用户门户与机场业务集成

组合采用相邻的 `airport-stack` 项目：SNTP Vue 页面 → 独立 Go 商城/统一账本 → airport-node（Xray 或 sing-box）。Marzban 保留旧商业账户兼容。`sb-manager-web` 继续管理独立的 sb-manager/sing-box 服务器，并提供业务后台入口。

| 组件 | 数据和操作归属 |
| --- | --- |
| `/root/proj/sntp` | 用户门户的静态页面资源；生产不运行其中的模拟服务器 |
| `/root/proj/airport-stack` | 客户账号、真实套餐、订单、支付验签、开通重试 |
| Go 控制中心 / airport-node | 两种商业核心共用个人凭据、套餐、用量、到期、封禁与订阅 |
| Marzban / Marzban-node | 旧商业用户的兼容后端，需显式迁移到统一账本 |
| sb-manager-web / sb-manager | 既有 sing-box 服务器运维、Agent、任务、备份 |

客户账号、商城管理员、Marzban 管理员、sb-manager-web 管理员分别认证。客户接口不能提交 sb 运维任务。现有 sb 节点的共享订阅没有接入商城的独立计量体系，因此不会自动作为商业用户的套餐节点；新商业节点通过 airport-node 接入并验证，使用独立进程、端口和计量目录；不要让两个管理器共用原 sb-manager 配置。

## 配置业务入口

在控制端原有 `config.json` 顶层添加，保留其他配置：

```json
{
  "airport": {
    "portal_url": "https://panel.example.com/",
    "store_admin_url": "https://panel.example.com/shop/admin/",
    "node_admin_url": "https://panel.example.com/shop/admin/nodes/"
  }
}
```

更新二进制并重启控制端后，总览侧栏显示三个入口。URL 必须是 HTTPS，不能包含账号密码、查询参数或片段；空值不显示。这里是独立服务入口，不是单点登录，也不会把管理员密码转发给其他服务。

## 导出与部署前端

完整说明见 `airport-stack/docs/PORTAL.md`。简要步骤：

```bash
cd /root/proj/airport-stack
python3 scripts/prepare-portal.py /root/proj/sntp
# 已完成中心与商城初始化后：
STORE_PORTAL_ENABLED=1 ./scripts/store-compose.sh build storefront
STORE_PORTAL_ENABLED=1 ./scripts/store-compose.sh up -d --wait
```

SNTP 开放注册、登录、套餐购买、订单和订阅中心。账号与密码重置复用商城原生页面。现有交易规则支持每 30 天恢复额度的周期套餐、不限时流量包和保留旧语义的累计套餐；提前续费不提前补流量，不自动扣款。未接入的媒体、返佣、流量明细、订阅规则等入口被禁用，未知 API 返回错误，不读取演示快照。

域名、商户支付、SMTP、远程节点和公网握手需要按实际部署配置及验收。仓库里的本地测试不会替代真实收款和公网连接验收。

Go 商城的部署、后端互锁和旧账本迁移见相邻 `airport-stack/docs/GO_COMMERCE.md`。商城管理入口仍为 `/shop/admin/`；新个人配置从 `/shop/sub/*` 导出。

统一节点安装、逐用户订阅重置、迁移及计量故障边界见相邻 `airport-stack/docs/NATIVE_NODES.md` 和 `ARCHITECTURE.md`。Marzban 原后台仍位于 `/dashboard/`，业务与运维继续独立认证。
