package runner

import (
	"strings"
	"testing"
)

func TestXrayAndUserLimitOperationMappings(t *testing.T) {
	tests := []struct {
		action string
		args   map[string]any
		want   string
	}{
		{"user.stats", map[string]any{"node_id": "edge"}, "user stats --json edge"},
		{"user.limit.quota", map[string]any{"node_id": "edge", "user_id": "alice", "quota": "100G", "reset_day": 1.0}, "user limit edge alice --quota 100G --reset-day 1"},
		{"user.limit.quota", map[string]any{"node_id": "edge", "user_id": "alice", "quota": "unlimited"}, "user limit edge alice --quota unlimited"},
		{"user.limit.days", map[string]any{"node_id": "edge", "user_id": "alice", "days": 30.0}, "user limit edge alice --days 30"},
		{"user.limit.ip", map[string]any{"node_id": "edge", "user_id": "alice", "ip_limit": 2.0}, "user limit edge alice --ip-limit 2"},
		{"user.limit.clear", map[string]any{"node_id": "edge", "user_id": "alice"}, "user limit edge alice --clear"},
		{"user.subscription", map[string]any{"mode": "mihomo", "user": "edge:alice"}, "subscription create never mihomo --user edge:alice --live"},
		{"vless.transport", map[string]any{"id": "edge", "transport": "xhttp", "security": "tls", "path": "/x", "xhttp_mode": "auto"}, "node set edge --transport xhttp --security tls --path /x --xhttp-mode auto"},
		{"vless.fallback", map[string]any{"id": "edge", "dest": "127.0.0.1:8080"}, "node set edge --fallback-dest 127.0.0.1:8080"},
		{"vless.pin", map[string]any{"id": "edge", "sha256": strings.Repeat("ab", 32)}, "node set edge --pinned-cert-sha256 " + strings.Repeat("ab", 32)},
		{"xray.balancer.set", map[string]any{"tag": "pool", "selectors": "warp,hk", "fallback": "direct"}, "xray balancer set pool --selectors warp,hk --strategy leastPing --fallback direct"},
		{"xray.route.add", map[string]any{"user": "edge:alice", "domain": "domain:openai.com", "to": "balancer:pool"}, "xray route add --user edge:alice --domain domain:openai.com --to balancer:pool"},
		{"xray.route.add", map[string]any{"ip": "10.0.0.0/8,192.0.2.1", "to": "block"}, "xray route add --ip 10.0.0.0/8,192.0.2.1 --to block"},
		{"xray.route.default", map[string]any{"to": "direct"}, "xray route default direct"},
		{"xray.outbound.add", map[string]any{"tag": "hk", "json": `{"protocol":"socks"}`, "via": "warp"}, `xray outbound add hk --json {"protocol":"socks"} --via warp`},
		{"notify.bot.enable", map[string]any{"admins": "12345,678"}, "notify bot enable --admin 12345,678"},
	}
	for _, test := range tests {
		command, err := ActionCommand(test.action, test.args)
		if err != nil {
			t.Fatalf("%s: %v", test.action, err)
		}
		if got := strings.Join(command, " "); got != test.want {
			t.Fatalf("%s: got %q want %q", test.action, got, test.want)
		}
	}
}

func TestXrayAndUserLimitOperationBoundaries(t *testing.T) {
	invalid := []struct {
		action string
		args   map[string]any
	}{
		{"user.limit.quota", map[string]any{"node_id": "edge", "user_id": "alice", "quota": "100G;reboot"}},
		{"user.limit.ip", map[string]any{"node_id": "edge", "user_id": "alice", "ip_limit": 0.0}},
		{"user.subscription", map[string]any{"user": "edge"}},
		{"user.subscription", map[string]any{"user": "edge:../alice"}},
		{"vless.fallback", map[string]any{"id": "edge", "dest": "--help"}},
		{"vless.fallback", map[string]any{"id": "edge", "dest": "99999"}},
		{"vless.pin", map[string]any{"id": "edge", "sha256": "abc"}},
		{"vless.transport", map[string]any{"id": "edge", "transport": "quic"}},
		{"xray.route.add", map[string]any{"domain": "geosite:cn", "to": "direct"}},
		{"xray.route.add", map[string]any{"ip": "not-an-ip", "to": "direct"}},
		{"xray.route.add", map[string]any{"to": "Bad Tag"}},
		{"xray.outbound.add", map[string]any{"tag": "hk", "json": "[1,2]"}},
		{"notify.bot.enable", map[string]any{"admins": "-1"}},
	}
	for _, test := range invalid {
		if command, err := ActionCommand(test.action, test.args); err == nil {
			t.Fatalf("%s accepted invalid input: %v", test.action, command)
		}
	}
	for _, action := range []string{"user.subscription", "xray.outbound.add"} {
		op, ok := LookupOperation(action)
		if !ok || !op.Private || !op.AdminOnly {
			t.Fatalf("%s must be private and admin-only", action)
		}
	}
}
