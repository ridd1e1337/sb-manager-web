package runner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationInputBoundaries(t *testing.T) {
	tests := []struct {
		action string
		args   map[string]any
	}{
		{"tcp.plan", map[string]any{"bandwidth": 1e9, "rtt": 30.0}},
		{"tcp.enable", map[string]any{"bandwidth": 100.0, "rtt": 2.5}},
		{"tcp.status", map[string]any{"shell": "reboot"}},
		{"network.ping", map[string]any{"host": "--help"}},
		{"network.speed", map[string]any{"host": "example.com", "seconds": 31.0}},
		{"network.compare", map[string]any{"before": "../../secret", "after": "20260923T000000Z-12345678"}},
		{"traffic.group.set", map[string]any{"id": "group", "nodes": "one,one", "quota": "100G"}},
		{"traffic.group.set", map[string]any{"id": "group", "nodes": "one", "quota": "100G", "reset_day": 29.0}},
		{"traffic.shaping.enable", map[string]any{"interface": "lo", "capacity": "1G"}},
		{"node.expiry.at", map[string]any{"id": "node", "at": "2020-01-01T00:00:00Z"}},
		{"tunnel.route.add", map[string]any{"id": "route", "domain": "app.example.com", "service": "http://169.254.169.254:80"}},
		{"tunnel.managed", map[string]any{"tunnel_id": "11111111-2222-3333-4444-555555555555", "credentials_file": "../secret.json"}},
		{"substore.source.add", map[string]any{"name": "source", "url": "https://user:password@example.com/sub/token"}},
		{"substore.source.add", map[string]any{"name": "source", "url": "http://public.example.com/sub/token"}},
		{"substore.source.add", map[string]any{"name": "source", "url": "https://example.com:99999/sub/token"}},
		{"substore.restore", map[string]any{"name": "../../etc/shadow"}},
		{"subscription.create", map[string]any{"duration": "never"}},
		{"subscription.create", map[string]any{"duration": "30d", "live": "true"}},
		{"subscription.create", map[string]any{"base_url": "https://example.com/?token=value"}},
		{"subscription.revoke-id", map[string]any{"id": "arbitrary-token"}},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			if cmd, err := ActionCommand(test.action, test.args); err == nil {
				t.Fatalf("invalid request accepted: %v", cmd)
			}
		})
	}
	for _, protocol := range []string{"socks", "http", "mixed"} {
		command, err := ActionCommand("node.add", map[string]any{"id": "proxy", "protocol": protocol, "listen": "127.0.0.1"})
		if err != nil || !strings.Contains(strings.Join(command, " "), "--listen 127.0.0.1") {
			t.Fatalf("authenticated proxy unavailable: %v", err)
		}
	}
}

func TestOperationCatalogueContainsNoExecutionTemplates(t *testing.T) {
	data, err := json.Marshal(Operations())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\"command\"") || strings.Contains(string(data), "\"flag\"") {
		t.Fatal("internal command templates exposed")
	}
	for _, action := range []string{"subscription.create", "substore.source.add", "substore.access"} {
		op, ok := LookupOperation(action)
		if !ok || !op.Private || !op.AdminOnly {
			t.Fatalf("%s must be private and admin-only", action)
		}
	}
}

// This test executes actual upstream CLI commands against its own isolated
// test fixture. It verifies the public CLI contract, not a matching fake CLI.
func TestUpstreamOperationsContract(t *testing.T) {
	upstream := os.Getenv("SB_MANAGER_SOURCE")
	if upstream == "" {
		t.Skip("set SB_MANAGER_SOURCE to the sb-manager checkout for upstream integration")
	}
	upstream, err := filepath.Abs(upstream)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	script := "set -Eeuo pipefail\nsource " + quote(filepath.Join(upstream, "tests/feature-fixture.sh")) + "\n"
	script += "export SBM_SUBSCRIPTION_PORT=49876\n"
	cases := []struct {
		action string
		args   map[string]any
	}{
		{"manager.version", nil},
		{"node.add", map[string]any{"protocol": "mixed", "id": "contract-proxy", "port": float64(28471), "listen": "127.0.0.1", "address": "127.0.0.1"}},
		{"node.expiry.days", map[string]any{"id": "contract-proxy", "days": float64(30)}},
		{"node.expiry.status", map[string]any{"id": "contract-proxy"}},
		{"node.expiry.clear", map[string]any{"id": "contract-proxy"}},
		{"subscription.create", map[string]any{"duration": "never", "mode": "mixed", "live": true, "base_url": "https://sub.example.test"}},
		{"subscription.list", nil},
		{"substore.status", nil},
		{"tunnel.route.list", nil},
		{"network.history", nil},
		{"traffic.shaping.status", nil},
	}
	for _, test := range cases {
		script += "printf '%s\\n' " + quote("checking "+test.action) + "\n"
		cmd, err := ActionCommand(test.action, test.args)
		if err != nil {
			t.Fatal(err)
		}
		script += "bash " + quote(filepath.Join(upstream, "sb"))
		for _, arg := range cmd {
			script += " " + quote(arg)
		}
		script += " >\"$ROOT/result\"\n"
		if test.action == "subscription.list" {
			script += "jq -e 'any(.[]; .live and .expires_at_epoch==null)' \"$ROOT/result\" >/dev/null\n"
		}
		if test.action == "node.expiry.status" {
			script += "jq -e '.expiry.at != null' \"$ROOT/result\" >/dev/null\n"
		}
	}
	script += "printf 'PASS: upstream CLI contract\\n'\n"
	cmd := exec.Command("bash", "-c", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("upstream contract failed: %v\n%s", err, output)
	}
}
