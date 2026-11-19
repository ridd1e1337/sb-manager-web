package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Operation describes a reviewed CLI mapping and the form that invokes it.
// It is shared by the controller, root helper and Agent, never a shell command.
type Operation struct {
	Action      string           `json:"action"`
	Group       string           `json:"group"`
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	Fields      []OperationField `json:"fields"`
	ReadOnly    bool             `json:"read_only"`
	AdminOnly   bool             `json:"admin_only"`
	Private     bool             `json:"private"`
	MinAlpha    int              `json:"min_alpha"`
	command     []string
}

type OperationField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Required bool     `json:"required"`
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
	Min      int      `json:"min,omitempty"`
	Max      int      `json:"max,omitempty"`
	flag     string
}

func field(key, label, kind, flag string, required bool) OperationField {
	return OperationField{Key: key, Label: label, Kind: kind, flag: flag, Required: required}
}
func number(key, label, flag string, min, max int, fallback string) OperationField {
	f := field(key, label, "number", flag, fallback == "")
	f.Min, f.Max, f.Default = min, max, fallback
	return f
}
func optionalNumber(key, label, flag string, min, max int) OperationField {
	f := number(key, label, flag, min, max, "")
	f.Required = false
	return f
}
func choice(key, label, flag, fallback string, options ...string) OperationField {
	f := field(key, label, "select", flag, false)
	f.Default, f.Options = fallback, options
	return f
}
func operation(action, group, title string, alpha int, read bool, command string, fields ...OperationField) Operation {
	if fields == nil {
		fields = []OperationField{}
	}
	return Operation{Action: action, Group: group, Title: title, MinAlpha: alpha, ReadOnly: read, command: strings.Fields(command), Fields: fields}
}

var operations = func() []Operation {
	ops := []Operation{
		operation("manager.version", "系统组件", "查看 sb-manager 版本", 0, true, "version"),
		operation("manager.check", "系统组件", "检查 sb-manager 更新", 30, true, "--json update --check"),
		operation("manager.update", "系统组件", "更新 sb-manager", 30, false, "--yes update"),
		operation("deps.status", "系统组件", "查看可选组件依赖", 30, true, "--json deps status"),
		operation("deps.install", "系统组件", "安装可选组件依赖", 30, false, "--yes deps install", choice("feature", "组件", "", "benchmark", "low-port", "traffic", "subscription", "bbr", "probe", "scheduler", "logrotate", "benchmark", "shaping", "substore")),
		operation("cloudflared.status", "系统组件", "Cloudflared 状态", 30, true, "--json cloudflared status"),
		operation("cloudflared.install", "系统组件", "安装 Cloudflared", 30, false, "--yes cloudflared install"),
		operation("tcp.status", "TCP 调优", "查看当前 TCP 设置", 31, true, "--json tcp status"),
		operation("tcp.plan", "TCP 调优", "预览 TCP 调优", 31, true, "--json tcp plan", number("bandwidth", "链路带宽（Mbps）", "--bandwidth", 1, 100000, ""), number("rtt", "实际 RTT（毫秒）", "--rtt", 1, 2000, "")),
		operation("tcp.enable", "TCP 调优", "应用 TCP 调优", 31, false, "--json tcp enable", number("bandwidth", "链路带宽（Mbps）", "--bandwidth", 1, 100000, ""), number("rtt", "实际 RTT（毫秒）", "--rtt", 1, 2000, "")),
		operation("tcp.disable", "TCP 调优", "恢复原 TCP 设置", 31, false, "tcp disable"),
		operation("network.ping", "网络诊断", "检测延迟与丢包", 31, true, "--json network ping", field("host", "目标主机/IP", "host", "", true), number("count", "次数", "--count", 1, 30, "10"), choice("family", "IP 协议", "", "auto", "auto", "4", "6")),
		operation("network.speed", "网络诊断", "运行 iperf3 吞吐测试", 32, false, "--json network speed", field("host", "自己的 iperf3 服务地址", "host", "", true), number("port", "端口", "--port", 1, 65535, "5201"), number("seconds", "时长（秒）", "--seconds", 1, 30, "10"), number("streams", "并发连接", "--streams", 1, 16, "1"), choice("direction", "方向", "--direction", "down", "up", "down")),
		operation("network.history", "网络诊断", "查看测速历史", 32, true, "--json network history"),
		operation("network.compare", "网络诊断", "对比同条件测速", 32, true, "--json network compare", field("before", "较早记录 ID", "record", "", true), field("after", "较晚记录 ID", "record", "", true)),
		operation("node.expiry.status", "节点有效期", "查看节点有效期", 32, true, "--json node expiry", field("id", "节点 ID", "id", "", true)),
		operation("node.expiry.days", "节点有效期", "延长节点有效期", 32, false, "node expiry", field("id", "节点 ID", "id", "", true), number("days", "延长天数", "--days", 1, 3650, "")),
		operation("node.expiry.at", "节点有效期", "设置到期时间", 32, false, "node expiry", field("id", "节点 ID", "id", "", true), field("at", "UTC 时间，如 2027-01-01T00:00:00Z", "timestamp", "--at", true)),
		operation("node.expiry.clear", "节点有效期", "清除节点期限", 32, false, "node expiry", field("id", "节点 ID", "id", "", true)),
		operation("traffic.group.status", "共享节点配额", "查看共享配额组", 32, true, "--json traffic group status"),
		operation("traffic.group.set", "共享节点配额", "保存共享配额组", 32, false, "traffic group set", field("id", "配额组 ID", "id", "", true), field("nodes", "成员节点 ID（逗号分隔）", "ids", "--nodes", true), field("quota", "额度，如 500G", "quantity", "--quota", true), number("reset_day", "每月重置日", "--reset-day", 1, 28, "1"), choice("quota_mode", "统计方式", "--quota-mode", "total", "total", "download")),
		operation("traffic.group.remove", "共享节点配额", "移除共享配额组", 32, false, "traffic group remove", field("id", "配额组 ID", "id", "", true)),
		operation("traffic.group.reset", "共享节点配额", "清零共享组用量", 32, false, "traffic group reset", field("id", "配额组 ID", "id", "", true)),
		operation("traffic.shaping.status", "网卡整形", "查看整形状态", 32, true, "--json traffic shaping status"),
		operation("traffic.shaping.plan", "网卡整形", "预览下行整形", 32, true, "--json traffic shaping plan", field("interface", "网卡，如 eth0", "interface", "", true), field("capacity", "网卡总容量，如 1G", "quantity", "--capacity", true)),
		operation("traffic.shaping.enable", "网卡整形", "启用下行整形", 32, false, "traffic shaping enable", field("interface", "网卡，如 eth0", "interface", "", true), field("capacity", "网卡总容量，如 1G", "quantity", "--capacity", true)),
		operation("traffic.shaping.disable", "网卡整形", "恢复原网卡队列", 32, false, "traffic shaping disable"),
		operation("tunnel.managed", "Tunnel 多路由", "配置本地托管 Tunnel", 32, false, "tunnel managed", field("tunnel_id", "Tunnel UUID", "uuid", "", true), field("credentials_file", "目标机 /etc/sb-manager/secrets/ 下的凭据文件名", "credential-file", "", true)),
		operation("tunnel.route.list", "Tunnel 多路由", "查看入口路由", 32, true, "--json tunnel route list"),
		operation("tunnel.route.add", "Tunnel 多路由", "保存域名与路径路由", 32, false, "tunnel route add", field("id", "路由 ID", "id", "", true), field("domain", "入口域名", "domain", "", true), field("service", "本机服务，如 http://127.0.0.1:8080", "local-url", "", true), field("path", "路径正则（可留空）", "text", "", false)),
		operation("tunnel.route.remove", "Tunnel 多路由", "移除入口路由", 32, false, "tunnel route remove", field("id", "路由 ID", "id", "", true)),
		operation("substore.status", "Sub-Store", "查看组件状态", 32, true, "--json substore status"),
		operation("substore.install", "Sub-Store", "安装 Sub-Store", 32, false, "--yes substore install", field("version", "后端版本（空为上游默认）", "version", "--version", false), field("frontend_version", "前端版本（可留空）", "version", "--frontend-version", false), number("port", "本机端口", "--port", 1024, 65535, "3001")),
		operation("substore.update", "Sub-Store", "更新 Sub-Store", 32, false, "--yes substore update", field("version", "后端版本（空为上游默认）", "version", "--version", false), field("frontend_version", "前端版本（可留空）", "version", "--frontend-version", false)),
		operation("substore.enable", "Sub-Store", "启用 Sub-Store", 32, false, "substore enable"),
		operation("substore.disable", "Sub-Store", "停用 Sub-Store", 32, false, "substore disable"),
		operation("substore.access", "Sub-Store", "显示私有访问地址", 32, true, "substore access"),
		operation("substore.sync", "Sub-Store", "接入本机动态来源", 34, false, "substore sync", field("name", "来源名称", "id", "", true)),
		operation("substore.backup", "Sub-Store", "创建组件备份", 32, false, "substore backup", field("name", "备份名称（不含扩展名）", "backup", "", true)),
		operation("substore.restore", "Sub-Store", "恢复组件备份", 32, false, "substore restore", field("name", "已备份的名称（不含扩展名）", "backup", "", true)),
		operation("substore.source.list", "订阅来源聚合", "查看来源清单", 34, true, "--json substore source list"),
		operation("substore.source.add", "订阅来源聚合", "接入其他服务器订阅", 34, false, "substore source add", field("name", "来源名称", "id", "", true), field("url", "HTTPS 动态订阅 URL", "source-url", "", true), field("collection", "组合名称（空为 sb-manager-all）", "id", "", false)),
		operation("substore.source.check", "订阅来源聚合", "检查来源可用性", 34, true, "substore source check", field("name", "来源名称", "id", "", true)),
		operation("substore.source.remove", "订阅来源聚合", "移除来源", 34, false, "substore source remove", field("name", "来源名称", "id", "", true)),
		operation("subscription.status", "动态订阅", "查看本机订阅服务", 34, true, "--json subscription status"),
		operation("subscription.list", "动态订阅", "查看已发放订阅", 34, true, "--json subscription list"),
		operation("subscription.create", "动态订阅", "生成动态或快照订阅", 34, false, "subscription create", field("duration", "有效期，如 30d、24h、never", "duration", "", false), choice("mode", "客户端模式", "", "mixed", "mixed", "tun"), field("live", "节点变更自动更新", "checkbox", "--live", false), field("base_url", "已配置的 HTTPS 订阅入口（可留空）", "base-url", "--base-url", false)),
		operation("subscription.revoke-id", "动态订阅", "按 ID 撤销订阅", 34, false, "subscription revoke", field("id", "订阅 ID（12 位）", "subscription-id", "", true)),
		// sb-manager alpha.73-76: Xray VLESS, per-user limits, routing and bot.
		operation("vless.transport", "VLESS 参数", "修改传输与安全层", 73, false, "node set", field("id", "VLESS 节点 ID", "id", "", true), choice("transport", "传输", "--transport", "raw", "raw", "ws", "grpc", "httpupgrade", "xhttp", "kcp", "hysteria"), choice("security", "安全层", "--security", "tls", "tls", "reality", "none"), field("path", "路径（WS/HTTPUpgrade/XHTTP）", "url-path", "--path", false), field("host", "Host（可留空）", "domain", "--host", false), choice("xhttp_mode", "XHTTP 模式", "--xhttp-mode", "", "", "auto", "packet-up", "stream-up", "stream-one")),
		operation("vless.fallback", "VLESS 参数", "设置回落（RAW + TLS）", 74, false, "node set", field("id", "VLESS 节点 ID", "id", "", true), field("dest", "回落目标：端口、地址:端口或 none", "fallback-dest", "--fallback-dest", true)),
		operation("vless.sniffing", "VLESS 参数", "设置流量嗅探", 74, false, "node set", field("id", "VLESS 节点 ID", "id", "", true), choice("sniffing", "嗅探", "--sniffing", "on", "on", "route-only", "off")),
		operation("vless.pin", "VLESS 参数", "固定 TLS 证书指纹", 74, false, "node set", field("id", "VLESS 节点 ID", "id", "", true), field("sha256", "证书 SHA-256（多个用逗号分隔）", "sha256s", "--pinned-cert-sha256", true)),
		operation("user.stats", "用户流量与限额", "查看用户流量、限额与在线 IP", 74, true, "user stats --json", field("node_id", "节点 ID（留空为全部）", "id", "", false)),
		operation("user.limit.quota", "用户流量与限额", "设置用户流量配额", 74, false, "user limit", field("node_id", "节点 ID", "id", "", true), field("user_id", "用户 ID", "id", "", true), field("quota", "配额，如 100G 或 unlimited", "quota", "--quota", true), optionalNumber("reset_day", "每月重置日（留空为不重置）", "--reset-day", 1, 28)),
		operation("user.limit.days", "用户流量与限额", "续期用户", 74, false, "user limit", field("node_id", "节点 ID", "id", "", true), field("user_id", "用户 ID", "id", "", true), number("days", "续期天数", "--days", 1, 3650, "")),
		operation("user.limit.ip", "用户流量与限额", "设置在线 IP 上限", 74, false, "user limit", field("node_id", "节点 ID", "id", "", true), field("user_id", "用户 ID", "id", "", true), number("ip_limit", "同时在线 IP 数", "--ip-limit", 1, 1024, "")),
		operation("user.limit.clear", "用户流量与限额", "清除用户全部限额", 74, false, "user limit", field("node_id", "节点 ID", "id", "", true), field("user_id", "用户 ID", "id", "", true)),
		operation("user.usage.reset", "用户流量与限额", "清零本周期用户流量", 74, false, "user reset-usage", field("node_id", "节点 ID", "id", "", true), field("user_id", "用户 ID", "id", "", true)),
		operation("user.subscription", "用户流量与限额", "生成用户动态订阅", 75, false, "subscription create never", choice("mode", "客户端格式", "", "mixed", "mixed", "tun", "xray", "mihomo"), field("user", "用户 NODE_ID:USER_ID", "user-ref", "--user", true)),
		operation("xray.traffic", "Xray 出站与路由", "入站/出站流量", 76, true, "xray traffic --json"),
		operation("xray.routing", "Xray 出站与路由", "查看出站、负载均衡与规则", 76, true, "xray routing --json"),
		operation("xray.outbound.add", "Xray 出站与路由", "添加原生出站", 76, false, "xray outbound add", field("tag", "出站标签", "id", "", true), field("json", "Xray outbound JSON", "json-object", "--json", true), field("via", "链式经由出站（可留空）", "id", "--via", false)),
		operation("xray.outbound.remove", "Xray 出站与路由", "删除出站", 76, false, "xray outbound remove", field("tag", "出站标签", "id", "", true)),
		operation("xray.warp.register", "Xray 出站与路由", "注册 WARP 出站", 76, false, "--yes xray warp --register", field("tag", "出站标签", "id", "--tag", false)),
		operation("xray.balancer.set", "Xray 出站与路由", "设置负载均衡", 76, false, "xray balancer set", field("tag", "负载均衡标签", "id", "", true), field("selectors", "成员出站（逗号分隔）", "ids", "--selectors", true), choice("strategy", "策略", "--strategy", "leastPing", "random", "roundRobin", "leastPing", "leastLoad"), field("fallback", "回退出站（可留空）", "id", "--fallback", false)),
		operation("xray.balancer.remove", "Xray 出站与路由", "删除负载均衡", 76, false, "xray balancer remove", field("tag", "负载均衡标签", "id", "", true)),
		operation("xray.route.add", "Xray 出站与路由", "添加分流规则", 76, false, "xray route add", field("node", "节点 ID（可留空）", "id", "--node", false), field("user", "用户 NODE_ID:USER_ID（可留空）", "user-ref", "--user", false), field("domain", "域名 domain:/full:/keyword:/regexp:（可留空）", "route-domain", "--domain", false), field("ip", "IP CIDR（逗号分隔，可留空）", "cidrs", "--ip", false), field("to", "出口：出站标签、block 或 balancer:标签", "route-target", "--to", true)),
		operation("xray.route.remove", "Xray 出站与路由", "删除分流规则", 76, false, "xray route remove", number("index", "规则序号", "", 1, 1000, "")),
		operation("xray.route.default", "Xray 出站与路由", "设置默认出口", 76, false, "xray route default", field("to", "direct、出站标签或 balancer:标签", "route-target", "", true)),
		operation("notify.bot.status", "Telegram 机器人", "查看机器人状态", 76, true, "notify bot status"),
		operation("notify.bot.enable", "Telegram 机器人", "启用命令机器人", 76, false, "notify bot enable", field("admins", "管理员 Telegram 用户 ID（逗号分隔）", "tg-ids", "--admin", true)),
		operation("notify.bot.disable", "Telegram 机器人", "停用命令机器人", 76, false, "notify bot disable"),
	}
	for i := range ops {
		op := &ops[i]
		switch op.Action {
		case "manager.update", "deps.install", "substore.install", "substore.update", "substore.restore", "tunnel.managed":
			op.AdminOnly = true
		case "substore.access", "substore.source.add", "subscription.create", "user.subscription", "xray.outbound.add":
			op.AdminOnly, op.Private = true, true
		case "xray.warp.register", "notify.bot.enable", "xray.outbound.remove":
			op.AdminOnly = true
		}
		if op.Action == "network.speed" {
			op.Description = "会产生实际测试流量；目标须运行你管理的 iperf3 服务。"
		}
		if strings.HasPrefix(op.Action, "traffic.group.") {
			op.Description = "这是 sing-box 节点端口共享额度，不是商城客户用量账本。"
		}
		if op.Action == "traffic.shaping.enable" {
			op.Description = "接管所选网卡的下行队列，总容量也影响该网卡的其他流量；请先预览。"
		}
		if op.Action == "substore.restore" || op.Action == "substore.backup" {
			op.Description = "备份保存在目标机 /var/lib/sb-manager/substore-backups/，含凭据，不进入任务输出。"
		}
		if op.Action == "tunnel.managed" {
			op.Description = "先将官方 Tunnel 凭据 JSON 保存到目标机 secrets 目录；此处只传文件名。"
		}
		if op.Action == "user.limit.ip" {
			op.Description = "需要 Xray 看到真实客户端 IP；只监听本机并经反代接入时请启用 PROXY protocol。"
		}
		if op.Action == "xray.warp.register" {
			op.Description = "会向 Cloudflare 注册一个免费 WARP 设备，并以用户态 WireGuard 接入 Xray。"
		}
		if op.Action == "xray.outbound.add" {
			op.Description = "出站凭据只保存在目标机 0600 secrets 文件，不进入状态快照。"
		}
		if op.Action == "subscription.create" {
			op.Description = "动态订阅包含当前和以后启用的节点凭据；never 只允许动态模式。"
			op.Fields[0].Default = "7d"
		}
	}
	return ops
}()

func Operations() []Operation { return append([]Operation(nil), operations...) }
func LookupOperation(action string) (Operation, bool) {
	for _, op := range operations {
		if op.Action == action {
			return op, true
		}
	}
	return Operation{}, false
}

var recordID = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$`)
var quantity = regexp.MustCompile(`^[1-9][0-9]{0,14}([kKmMgGtT]([iI]?[bB])?)?$`)
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
var uuidValue = regexp.MustCompile(`^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$`)
var subscriptionID = regexp.MustCompile(`^[a-f0-9]{12}$`)
var durationValue = regexp.MustCompile(`^[1-9][0-9]{0,4}[hd]$`)
var componentVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)
var quotaValue = regexp.MustCompile(`^(unlimited|[1-9][0-9]{0,14}([kKmMgGtTpP]([iI]?[bB])?)?)$`)
var userRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}:[a-z0-9][a-z0-9._-]{0,47}$`)
var routeTarget = regexp.MustCompile(`^(balancer:)?[a-z0-9][a-z0-9._-]{0,47}$`)
var routeDomain = regexp.MustCompile(`^(domain|full|keyword|regexp):[^,\s]+(,(domain|full|keyword|regexp):[^,\s]+)*$`)
var telegramIDs = regexp.MustCompile(`^[1-9][0-9]{0,15}(,[1-9][0-9]{0,15}){0,15}$`)
var sha256List = regexp.MustCompile(`^([0-9A-Fa-f:]{64,95})(,[0-9A-Fa-f:]{64,95}){0,7}$`)
var urlPath = regexp.MustCompile(`^/[A-Za-z0-9._~/%=?&-]{0,255}$`)

func operationCommand(op Operation, args map[string]any) ([]string, error) {
	known := map[string]bool{}
	command := append([]string(nil), op.command...)
	for _, f := range op.Fields {
		known[f.Key] = true
		raw, present := args[f.Key]
		if f.Kind == "checkbox" {
			if present {
				enabled, ok := raw.(bool)
				if !ok {
					return nil, fmt.Errorf("%s must be boolean", f.Key)
				}
				if enabled {
					command = append(command, f.flag)
				}
			}
			continue
		}
		value := f.Default
		if present {
			switch v := raw.(type) {
			case string:
				value = v
			case float64:
				if f.Kind != "number" || v != float64(int(v)) {
					return nil, fmt.Errorf("invalid %s", f.Key)
				}
				value = strconv.Itoa(int(v))
			default:
				return nil, fmt.Errorf("invalid %s type", f.Key)
			}
			if value == "" {
				value = f.Default
			}
		}
		if value == "" {
			if f.Required {
				return nil, fmt.Errorf("%s is required", f.Key)
			}
			continue
		}
		if err := validateOperationField(f, value); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Key, err)
		}
		if f.Key == "family" {
			if value != "auto" {
				command = append(command, "--ipv"+value)
			}
			continue
		}
		if f.Kind == "backup" {
			value = filepath.Join("/var/lib/sb-manager/substore-backups", value+".tar.gz")
		}
		if f.Kind == "credential-file" {
			value = filepath.Join("/etc/sb-manager/secrets", value)
		}
		if f.flag != "" {
			command = append(command, f.flag)
		}
		command = append(command, value)
	}
	for key := range args {
		if !known[key] {
			return nil, fmt.Errorf("unknown operation field: %s", key)
		}
	}
	if op.Action == "node.expiry.clear" || op.Action == "user.limit.clear" {
		command = append(command, "--clear")
	}
	if op.Action == "user.subscription" {
		command = append(command, "--live")
	}
	if op.Action == "subscription.create" {
		if args["duration"] == "never" && args["live"] != true {
			return nil, errors.New("never requires a live subscription")
		}
	}
	return command, nil
}

func validateOperationField(f OperationField, value string) error {
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") || strings.HasPrefix(value, "-") {
		return errors.New("invalid value")
	}
	valid := true
	switch f.Kind {
	case "id", "backup":
		valid = safeID.MatchString(value)
	case "credential-file":
		valid = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.json$`).MatchString(value)
	case "subscription-id":
		valid = subscriptionID.MatchString(value)
	case "ids":
		ids := strings.Split(value, ",")
		valid = len(ids) > 0 && len(ids) <= 128
		seen := map[string]bool{}
		for _, id := range ids {
			if !safeID.MatchString(id) || seen[id] {
				valid = false
			}
			seen[id] = true
		}
	case "number":
		n, err := strconv.Atoi(value)
		valid = err == nil && n >= f.Min && n <= f.Max
	case "select":
		valid = false
		for _, option := range f.Options {
			if value == option {
				valid = true
			}
		}
	case "quantity":
		valid = quantity.MatchString(value)
	case "interface":
		valid = value != "lo" && interfaceName.MatchString(value)
	case "record":
		valid = recordID.MatchString(value)
	case "uuid":
		valid = uuidValue.MatchString(value)
	case "version":
		valid = componentVersion.MatchString(value)
	case "domain":
		valid = safeDomain.MatchString(value)
	case "host":
		valid = net.ParseIP(value) != nil || value == "localhost" || safeDomain.MatchString(value)
	case "timestamp":
		t, err := time.Parse("2006-01-02T15:04:05Z", value)
		valid = err == nil && t.After(time.Now())
	case "duration":
		valid = value == "never" || durationValue.MatchString(value)
	case "text":
		valid = len(value) <= 512
	case "quota":
		valid = quotaValue.MatchString(value)
	case "user-ref":
		valid = userRef.MatchString(value)
	case "route-target":
		valid = routeTarget.MatchString(value)
	case "route-domain":
		valid = len(value) <= 2048 && routeDomain.MatchString(value)
	case "tg-ids":
		valid = telegramIDs.MatchString(value)
	case "sha256s":
		valid = sha256List.MatchString(value)
	case "url-path":
		valid = urlPath.MatchString(value)
	case "cidrs":
		parts := strings.Split(value, ",")
		valid = len(parts) <= 64
		for _, part := range parts {
			if _, _, err := net.ParseCIDR(part); err != nil && net.ParseIP(part) == nil {
				valid = false
			}
		}
	case "fallback-dest":
		if value == "none" {
			break
		}
		if n, err := strconv.Atoi(value); err == nil {
			valid = n >= 1 && n <= 65535
			break
		}
		host, port, err := net.SplitHostPort(value)
		n, perr := strconv.Atoi(port)
		valid = err == nil && perr == nil && n >= 1 && n <= 65535 && (net.ParseIP(host) != nil || host == "localhost" || safeDomain.MatchString(host))
	case "json-object":
		var object map[string]any
		valid = len(value) <= 4096 && json.Unmarshal([]byte(value), &object) == nil && object != nil
	case "source-url", "base-url", "local-url":
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(value, " \t") {
			return errors.New("invalid URL")
		}
		if u.Port() != "" {
			port, e := strconv.Atoi(u.Port())
			if e != nil || port < 1 || port > 65535 {
				return errors.New("invalid URL port")
			}
		}
		local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
		switch f.Kind {
		case "source-url":
			valid = u.Scheme == "https" || (u.Scheme == "http" && local)
		case "base-url":
			valid = u.Scheme == "https" && u.RawQuery == "" && regexp.MustCompile(`^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[-a-zA-Z0-9._~/]*)?$`).MatchString(value)
		case "local-url":
			valid = local && (u.Scheme == "http" || u.Scheme == "https") && u.Port() != "" && u.Path == "" && u.RawQuery == ""
		}
	}
	if !valid {
		return errors.New("value is outside allowed range or format")
	}
	return nil
}
