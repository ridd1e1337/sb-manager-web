package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Result struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

type Runner struct {
	Path    string
	Timeout time.Duration
}

var safeVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)
var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)
var safeProtocol = regexp.MustCompile(`^(vmess|ss|anytls|hy2|trojan|tuic|vless|naive|shadowtls|snell)$`)
var safeDomain = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

func ValidVersion(value string) bool {
	return safeVersion.MatchString(value)
}

func (r Runner) Run(ctx context.Context, args ...string) (Result, error) {
	if r.Path == "" {
		return Result{}, errors.New("sb path is empty")
	}
	if len(args) == 0 {
		return Result{}, errors.New("sb command is empty")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.Path, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if runCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, fmt.Errorf("sb command timed out after %s", timeout)
	}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("sb exited with status %d", result.ExitCode)
	}
	return result, err
}

func JSONArgs(command ...string) []string {
	return append([]string{"--json"}, command...)
}

func ActionCommand(action string, args map[string]any) ([]string, error) {
	switch action {
	case "status":
		return JSONArgs("status"), nil
	case "nodes.list":
		return JSONArgs("node", "list"), nil
	case "node.rotate":
		id, err := requiredID(args, "id")
		if err != nil {
			return nil, err
		}
		return []string{"node", "rotate", id}, nil
	case "node.template.list":
		return JSONArgs("node", "template", "list"), nil
	case "node.enable-all", "node.disable-all":
		verb := "enable-all"
		if action == "node.disable-all" {
			verb = "disable-all"
		}
		command := []string{"node", verb}
		if tag, _ := args["tag"].(string); tag != "" {
			if tag = safeArgument(tag, 128); tag == "" {
				return nil, errors.New("invalid tag")
			}
			command = append(command, "--tag", tag)
		}
		if region, _ := args["region"].(string); region != "" {
			if region = safeArgument(region, 128); region == "" {
				return nil, errors.New("invalid region")
			}
			command = append(command, "--region", region)
		}
		if len(command) == 2 {
			return nil, errors.New("tag or region is required")
		}
		return command, nil
	case "core.capabilities":
		return JSONArgs("core", "capabilities"), nil
	case "bbr.status":
		return JSONArgs("bbr", "status"), nil
	case "bbr.enable":
		return []string{"bbr", "enable"}, nil
	case "bbr.disable":
		return []string{"bbr", "disable"}, nil
	case "hy2-buffer.status":
		return JSONArgs("hy2", "buffer", "status"), nil
	case "hy2-buffer.enable":
		return []string{"hy2", "buffer", "enable"}, nil
	case "hy2-buffer.disable":
		return []string{"hy2", "buffer", "disable"}, nil
	case "realm.status":
		return JSONArgs("realm", "status"), nil
	case "realm.disable":
		return []string{"realm", "disable"}, nil
	case "realm.enable":
		return realmEnableCommand(args)
	case "core.check":
		return JSONArgs("core", "check"), nil
	case "core.update":
		version, _ := args["version"].(string)
		if version != "" {
			if !ValidVersion(version) {
				return nil, errors.New("invalid core version")
			}
			return []string{"core", "update", version}, nil
		}
		return []string{"core", "update"}, nil
	case "core.rollback":
		return []string{"core", "rollback"}, nil
	case "core.policy":
		policy, _ := args["policy"].(string)
		switch policy {
		case "manual", "notify", "patch", "stable":
		default:
			return nil, errors.New("invalid core policy")
		}
		return []string{"core", "policy", policy}, nil
	case "core.auto":
		return []string{"core", "auto"}, nil
	case "doctor":
		return JSONArgs("doctor"), nil
	case "doctor.repair-safe":
		return []string{"doctor", "--repair-safe"}, nil
	case "backup.create":
		return []string{"backup"}, nil
	case "restore":
		archive, _ := args["archive"].(string)
		if archive == "" || strings.ContainsAny(archive, "\r\n\x00") || (filepath.Ext(archive) != ".age" && !strings.HasSuffix(archive, ".tar.gz")) {
			return nil, errors.New("invalid backup archive")
		}
		return []string{"restore", archive, "--yes"}, nil
	case "health.check":
		return JSONArgs("health", "check"), nil
	case "logs":
		target, _ := args["target"].(string)
		if target == "" {
			target = "all"
		}
		if target != "all" && target != "singbox" && target != "tunnel" && target != "nginx" {
			return nil, errors.New("invalid log target")
		}
		lines := float64(100)
		if value, ok := args["lines"].(float64); ok {
			lines = value
		}
		if lines < 1 || lines > 1000 || lines != float64(int(lines)) {
			return nil, errors.New("invalid log lines")
		}
		return []string{"logs", target, fmt.Sprintf("%d", int(lines))}, nil
	case "node.enable", "node.disable", "node.delete":
		id, ok := args["id"].(string)
		if !ok || !safeID.MatchString(id) {
			return nil, errors.New("invalid node id")
		}
		verb := strings.TrimPrefix(action, "node.")
		return []string{"node", verb, id}, nil
	case "node.add":
		return nodeAddCommand(args)
	case "node.set":
		return nodeSetCommand(args)
	case "node.show":
		id, err := requiredID(args, "id")
		if err != nil {
			return nil, err
		}
		return JSONArgs("node", "show", id), nil
	case "node.share":
		id, err := requiredID(args, "id")
		if err != nil {
			return nil, err
		}
		command := []string{"share", id}
		if userID, _ := args["user_id"].(string); userID != "" {
			if !safeID.MatchString(userID) {
				return nil, errors.New("invalid user id")
			}
			command = append(command, "--user", userID)
		}
		if qr, _ := args["qr"].(bool); qr {
			command = append(command, "--qr")
		}
		return command, nil
	case "share.all":
		return []string{"share", "all"}, nil
	case "api.status":
		return JSONArgs("api", "status"), nil
	case "api.enable":
		port, _ := args["port"].(float64)
		if port == 0 {
			port = 9090
		}
		if port < 1 || port > 65535 || port != float64(int(port)) {
			return nil, errors.New("invalid API port")
		}
		command := []string{"api", "enable", fmt.Sprintf("%d", int(port))}
		if dashboard, _ := args["dashboard"].(bool); dashboard {
			command = append(command, "--dashboard")
		}
		return command, nil
	case "api.disable":
		return []string{"api", "disable"}, nil
	case "export.outbounds":
		return []string{"export", "outbounds"}, nil
	case "subscription.list":
		return JSONArgs("subscription", "list"), nil
	case "subscription.status":
		return JSONArgs("subscription", "status"), nil
	case "subscription.create":
		duration, _ := args["duration"].(string)
		mode, _ := args["mode"].(string)
		if duration == "" {
			duration = "7d"
		}
		if mode == "" {
			mode = "mixed"
		}
		if duration != "7d" && duration != "24h" {
			return nil, errors.New("invalid subscription duration")
		}
		if mode != "mixed" && mode != "tun" {
			return nil, errors.New("invalid subscription mode")
		}
		return []string{"subscription", "create", duration, mode}, nil
	case "subscription.revoke":
		token, _ := args["token"].(string)
		if len(token) < 16 || len(token) > 256 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, errors.New("invalid subscription token")
		}
		return []string{"subscription", "revoke", token}, nil
	case "users.list":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		return JSONArgs("user", "list", nodeID), nil
	case "user.add":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		userID, err := requiredID(args, "user_id")
		if err != nil {
			return nil, err
		}
		name, _ := args["name"].(string)
		if name == "" {
			name = userID
		}
		if len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
			return nil, errors.New("invalid user name")
		}
		return []string{"user", "add", nodeID, userID, name}, nil
	case "user.enable", "user.disable", "user.delete", "user.rotate":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		userID, err := requiredID(args, "user_id")
		if err != nil {
			return nil, err
		}
		return []string{"user", strings.TrimPrefix(action, "user."), nodeID, userID}, nil
	case "cert.list":
		return JSONArgs("cert", "list"), nil
	case "cert.issue":
		domain, _ := args["domain"].(string)
		if !safeDomain.MatchString(domain) {
			return nil, errors.New("invalid certificate domain")
		}
		command := []string{"cert", "issue", domain}
		if email, _ := args["email"].(string); email != "" {
			if len(email) > 254 || !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n\x00") {
				return nil, errors.New("invalid email")
			}
			command = append(command, email)
		}
		return command, nil
	case "cert.renew":
		return []string{"cert", "renew"}, nil
	case "cert.inspect":
		domain, _ := args["domain"].(string)
		if !safeDomain.MatchString(domain) {
			return nil, errors.New("invalid certificate domain")
		}
		return JSONArgs("cert", "inspect", domain), nil
	case "cert.setup-cloudflare":
		token, _ := args["token"].(string)
		if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, errors.New("Cloudflare token is required")
		}
		command := []string{"cert", "setup-cloudflare", token}
		if zone, _ := args["zone_id"].(string); zone != "" {
			if safeArgument(zone, 128) == "" {
				return nil, errors.New("invalid Cloudflare zone id")
			}
			command = append(command, zone)
		}
		if email, _ := args["email"].(string); email != "" {
			if safeArgument(email, 254) == "" {
				return nil, errors.New("invalid Cloudflare email")
			}
			command = append(command, email)
		}
		return command, nil
	case "health.status":
		return JSONArgs("health", "status"), nil
	case "health.enable":
		return []string{"health", "enable"}, nil
	case "health.disable":
		return []string{"health", "disable"}, nil
	case "config.validate":
		return JSONArgs("config", "validate"), nil
	case "config.diff":
		return JSONArgs("config", "diff"), nil
	case "firewall.status":
		return JSONArgs("firewall", "status"), nil
	case "firewall.ports":
		return JSONArgs("firewall", "ports"), nil
	case "firewall.ufw-allow":
		return []string{"firewall", "ufw-allow", "--yes"}, nil
	case "firewall.clear-iptables":
		return []string{"firewall", "clear-iptables", "--yes"}, nil
	case "firewall.fail2ban":
		return []string{"firewall", "fail2ban", "--yes"}, nil
	case "firewall.ufw":
		return []string{"firewall", "ufw", "--yes"}, nil
	case "mux.status":
		return JSONArgs("mux", "status"), nil
	case "mux.enable":
		port, _ := args["port"].(float64)
		if port == 0 {
			return []string{"mux", "enable"}, nil
		}
		if port < 1 || port > 65535 || port != float64(int(port)) {
			return nil, errors.New("invalid mux port")
		}
		return []string{"mux", "enable", fmt.Sprintf("%d", int(port))}, nil
	case "mux.disable":
		return []string{"mux", "disable"}, nil
	case "mux.route.list":
		return JSONArgs("mux", "route", "list"), nil
	case "mux.route.add":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		sni, _ := args["sni"].(string)
		if !safeDomain.MatchString(sni) {
			return nil, errors.New("invalid SNI")
		}
		command := []string{"mux", "route", "add", nodeID, sni}
		if value, ok := args["backend_port"].(float64); ok {
			if value < 1 || value > 65535 || value != float64(int(value)) {
				return nil, errors.New("invalid backend port")
			}
			command = append(command, fmt.Sprintf("%d", int(value)))
		}
		return command, nil
	case "mux.route.remove":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		return []string{"mux", "route", "remove", nodeID}, nil
	case "tunnel.status":
		return JSONArgs("tunnel", "status"), nil
	case "tunnel.stop":
		return []string{"tunnel", "stop"}, nil
	case "tunnel.refresh":
		return []string{"tunnel", "refresh"}, nil
	case "tunnel.fixed":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		domain, _ := args["domain"].(string)
		if !safeDomain.MatchString(domain) {
			return nil, errors.New("invalid tunnel domain")
		}
		token, _ := args["token"].(string)
		if len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, errors.New("invalid tunnel token")
		}
		command := []string{"tunnel", "fixed", nodeID, domain}
		if token != "" {
			command = append(command, token)
		}
		if address, _ := args["client_address"].(string); address != "" {
			command = append(command, address)
		}
		return command, nil
	case "tunnel.set-token":
		token, _ := args["token"].(string)
		if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, errors.New("invalid tunnel token")
		}
		return []string{"tunnel", "set-token", token}, nil
	case "notify.status":
		return JSONArgs("notify", "status"), nil
	case "notify.test":
		return []string{"notify", "test"}, nil
	case "notify.check":
		return []string{"notify", "check"}, nil
	case "notify.disable":
		return []string{"notify", "disable"}, nil
	case "notify.configure":
		provider, _ := args["provider"].(string)
		if provider != "telegram" && provider != "wecom" && provider != "webhook" {
			return nil, errors.New("invalid notification provider")
		}
		credentialFile, _ := args["credential_file"].(string)
		if credentialFile == "" || strings.ContainsAny(credentialFile, "\r\n\x00") {
			return nil, errors.New("notification credential file is required")
		}
		command := []string{"notify", "configure", provider, "--token-file", credentialFile}
		if chatID, _ := args["chat_id"].(string); chatID != "" {
			chatID = safeArgument(chatID, 128)
			if chatID == "" {
				return nil, errors.New("invalid notification chat id")
			}
			command = append(command, "--chat-id", chatID)
		}
		if thresholds, _ := args["thresholds"].(string); thresholds != "" {
			thresholds = safeArgument(thresholds, 64)
			if thresholds == "" {
				return nil, errors.New("invalid notification thresholds")
			}
			command = append(command, "--thresholds", thresholds)
		}
		return command, nil
	case "traffic.status":
		command := JSONArgs("traffic", "status")
		if nodeID, _ := args["node_id"].(string); nodeID != "" {
			if !safeID.MatchString(nodeID) {
				return nil, errors.New("invalid node id")
			}
			command = append(command, nodeID)
		}
		return command, nil
	case "traffic.set":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		command := []string{"traffic", "set", nodeID}
		for _, field := range []struct{ key, flag string }{{"quota", "--quota"}, {"reset_day", "--reset-day"}, {"rate", "--rate"}, {"upload_rate", "--upload-rate"}, {"download_rate", "--download-rate"}, {"quota_mode", "--quota-mode"}} {
			if value, ok := args[field.key].(string); ok && value != "" {
				if safeArgument(value, 64) == "" {
					return nil, errors.New("invalid traffic value")
				}
				command = append(command, field.flag, value)
			}
		}
		if len(command) == 3 {
			return nil, errors.New("traffic.set requires a field")
		}
		return command, nil
	case "traffic.disable", "traffic.remove", "traffic.reset":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		command := []string{"traffic", strings.TrimPrefix(action, "traffic."), nodeID}
		if action == "traffic.reset" {
			command = append(command, "--yes")
		}
		return command, nil
	case "traffic.reconcile":
		return []string{"traffic", "reconcile"}, nil
	case "health.configure":
		command := []string{"health", "configure"}
		for _, field := range []struct{ key, flag string }{{"disk_free", "--disk-free"}, {"memory_max", "--memory-max"}, {"load_per_core", "--load-per-core"}, {"inode_max", "--inode-max"}, {"fd_max", "--fd-max"}, {"banned_warn", "--banned-warn"}, {"restart_warn", "--restart-warn"}} {
			if value, ok := args[field.key].(string); ok && value != "" {
				if safeArgument(value, 32) == "" {
					return nil, errors.New("invalid health value")
				}
				command = append(command, field.flag, value)
			}
		}
		if len(command) == 2 {
			return nil, errors.New("health.configure requires a field")
		}
		return command, nil
	case "settings.show":
		return JSONArgs("settings", "show"), nil
	case "settings.detect-ip":
		return []string{"settings", "detect-ip"}, nil
	case "settings.address":
		address, _ := args["address"].(string)
		if address != "auto" && !safeDomain.MatchString(address) && net.ParseIP(address) == nil {
			return nil, errors.New("invalid default server address")
		}
		return []string{"settings", "address", address}, nil
	case "settings.outbound-ip":
		strategy, _ := args["strategy"].(string)
		if strategy != "prefer_ipv4" && strategy != "prefer_ipv6" && strategy != "ipv4_only" {
			return nil, errors.New("invalid outbound IP strategy")
		}
		return []string{"settings", "outbound-ip", strategy}, nil
	case "settings.dns":
		kind, _ := args["kind"].(string)
		value, _ := args["value"].(string)
		if kind != "optimistic" && kind != "optimistic-timeout" && kind != "timeout" {
			return nil, errors.New("invalid DNS setting")
		}
		if safeArgument(value, 32) == "" {
			return nil, errors.New("invalid DNS value")
		}
		return []string{"settings", "dns", kind, value}, nil
	case "service.restart":
		return []string{"restart"}, nil
	case "doctor.network":
		return []string{"doctor", "--network"}, nil
	case "probe":
		nodeID, err := requiredID(args, "node_id")
		if err != nil {
			return nil, err
		}
		return []string{"probe", nodeID}, nil
	case "cloudflared.update":
		return []string{"cloudflared", "update"}, nil
	case "acme.update":
		return []string{"acme", "update"}, nil
	case "repair":
		return []string{"repair", "--safe"}, nil
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

func safeArgument(value string, max int) string {
	if len(value) > max || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func requiredID(args map[string]any, key string) (string, error) {
	value, _ := args[key].(string)
	if !safeID.MatchString(value) {
		return "", fmt.Errorf("invalid %s", strings.ReplaceAll(key, "_", " "))
	}
	return value, nil
}

func nodeAddCommand(args map[string]any) ([]string, error) {
	protocol, _ := args["protocol"].(string)
	id, _ := args["id"].(string)
	if !safeProtocol.MatchString(protocol) || !safeID.MatchString(id) {
		return nil, errors.New("invalid node protocol or id")
	}
	command := []string{"node", "add", protocol, "--id", id}
	for _, field := range []struct{ key, flag string }{{"name", "--name"}, {"domain", "--domain"}, {"address", "--address"}, {"path", "--path"}, {"method", "--method"}, {"network", "--network"}, {"obfs", "--obfs"}, {"obfs_host", "--obfs-host"}, {"snell_version", "--snell-version"}, {"snell_mode", "--snell-mode"}, {"bbr_profile", "--bbr-profile"}, {"masquerade", "--masquerade"}, {"security", "--security"}, {"flow", "--flow"}, {"handshake_server", "--handshake-server"}, {"congestion_control", "--congestion-control"}, {"strict_mode", "--strict-mode"}, {"wildcard_sni", "--wildcard-sni"}, {"realm_id", "--realm-id"}, {"realm_ip_version", "--realm-ip-version"}} {
		if value, ok := args[field.key].(string); ok && value != "" {
			if len(value) > 253 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, errors.New("invalid node value")
			}
			command = append(command, field.flag, value)
		}
	}
	if port, ok := args["port"].(float64); ok {
		if port < 1 || port > 65535 || port != float64(int(port)) {
			return nil, errors.New("invalid node port")
		}
		command = append(command, "--port", fmt.Sprintf("%d", int(port)))
	}
	for _, field := range []struct{ key, flag string }{{"obfs_min_packet_size", "--obfs-min-packet-size"}, {"obfs_max_packet_size", "--obfs-max-packet-size"}, {"handshake_port", "--handshake-port"}} {
		if value, ok := args[field.key].(float64); ok {
			if value < 1 || value > 65535 || value != float64(int(value)) {
				return nil, errors.New("invalid node numeric value")
			}
			command = append(command, field.flag, fmt.Sprintf("%d", int(value)))
		}
	}
	if value, ok := args["disable_chrome_parrot"].(bool); ok && value {
		command = append(command, "--disable-chrome-parrot")
	}
	if value, ok := args["brutal_debug"].(bool); ok && value {
		command = append(command, "--brutal-debug")
	}
	if value, ok := args["realm_port_mapping"].(bool); ok && value {
		command = append(command, "--realm-port-mapping")
	}
	if value, ok := args["quic"].(bool); ok && value {
		command = append(command, "--quic")
	}
	if disabled, ok := args["disabled"].(bool); ok && disabled {
		command = append(command, "--disabled")
	}
	return command, nil
}

func realmEnableCommand(args map[string]any) ([]string, error) {
	port, ok := args["port"].(float64)
	if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
		return nil, errors.New("invalid Realm port")
	}
	publicURL, _ := args["public_url"].(string)
	parsed, err := url.Parse(publicURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid Realm public URL")
	}
	listen, _ := args["listen"].(string)
	if listen == "" {
		listen = "::"
	}
	if len(listen) > 128 || strings.ContainsAny(listen, "\r\n\x00") {
		return nil, errors.New("invalid Realm listen address")
	}
	command := []string{"realm", "enable", fmt.Sprintf("%d", int(port)), publicURL, "--listen", listen}
	if domain, _ := args["tls_domain"].(string); domain != "" {
		if !safeDomain.MatchString(domain) {
			return nil, errors.New("invalid Realm TLS domain")
		}
		command = append(command, "--tls-domain", domain)
	}
	max := float64(0)
	if value, present := args["max_realms"]; present {
		var ok bool
		max, ok = value.(float64)
		if !ok || max < 0 || max > 1000000 || max != float64(int(max)) {
			return nil, errors.New("invalid Realm max_realms")
		}
	}
	if max > 0 {
		command = append(command, "--max-realms", fmt.Sprintf("%d", int(max)))
	}
	return command, nil
}

func nodeSetCommand(args map[string]any) ([]string, error) {
	id, _ := args["id"].(string)
	if !safeID.MatchString(id) {
		return nil, errors.New("invalid node id")
	}
	command := []string{"node", "set", id}
	for _, field := range []struct{ key, flag string }{
		{"name", "--name"}, {"address", "--address"}, {"domain", "--domain"}, {"path", "--path"},
		{"remark", "--remark"}, {"region", "--region"}, {"purpose", "--purpose"}, {"line", "--line"}, {"tags", "--tags"},
		{"method", "--method"}, {"network", "--network"}, {"obfs", "--obfs"}, {"obfs_host", "--obfs-host"},
		{"bbr_profile", "--bbr-profile"}, {"masquerade", "--masquerade"}, {"security", "--security"}, {"flow", "--flow"},
		{"handshake_server", "--handshake-server"}, {"congestion_control", "--congestion-control"}, {"strict_mode", "--strict-mode"},
		{"wildcard_sni", "--wildcard-sni"}, {"snell_version", "--snell-version"}, {"snell_mode", "--snell-mode"},
		{"realm_id", "--realm-id"}, {"realm_ip_version", "--realm-ip-version"},
	} {
		if value, ok := args[field.key].(string); ok {
			if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, errors.New("invalid node value")
			}
			command = append(command, field.flag, value)
		}
	}
	for _, field := range []struct{ key, flag string }{
		{"port", "--port"}, {"obfs_min_packet_size", "--obfs-min-packet-size"},
		{"obfs_max_packet_size", "--obfs-max-packet-size"}, {"handshake_port", "--handshake-port"},
	} {
		if value, ok := args[field.key].(float64); ok {
			if value < 1 || value > 65535 || value != float64(int(value)) {
				return nil, fmt.Errorf("invalid %s", strings.ReplaceAll(field.key, "_", " "))
			}
			command = append(command, field.flag, fmt.Sprintf("%d", int(value)))
		}
	}
	for _, field := range []struct{ key, yes, no string }{
		{"disable_chrome_parrot", "--disable-chrome-parrot", "--enable-chrome-parrot"},
		{"brutal_debug", "--brutal-debug", "--no-brutal-debug"},
		{"realm_port_mapping", "--realm-port-mapping", "--no-realm-port-mapping"},
	} {
		if value, ok := args[field.key].(bool); ok {
			if value {
				command = append(command, field.yes)
			} else {
				command = append(command, field.no)
			}
		}
	}
	if clear, ok := args["clear_realm"].(bool); ok && clear {
		command = append(command, "--clear-realm")
	}
	if len(command) == 3 {
		return nil, errors.New("node.set requires at least one field")
	}
	return command, nil
}

func ResultJSON(result Result) json.RawMessage {
	data, _ := json.Marshal(result)
	return data
}
