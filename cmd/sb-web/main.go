package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/ridd1e1337/sb-manager-web/internal/agent"
	"github.com/ridd1e1337/sb-manager-web/internal/api"
	"github.com/ridd1e1337/sb-manager-web/internal/auth"
	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/helper"
	"github.com/ridd1e1337/sb-manager-web/internal/runner"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
)

const defaultConfigPath = "/etc/sb-manager-web/config.json"
const defaultInstallerURL = "https://github.com/ridd1e1337/sb-manager-web/raw/main/install.sh"

const (
	webLibDir       = "/usr/local/lib/sb-manager-web"
	webBinDir       = "/usr/local/bin"
	webSystemdDir   = "/etc/systemd/system"
	webOpenRCDir    = "/etc/init.d"
	webPeriodicDir  = "/etc/periodic"
	webService      = "sb-manager-web.service"
	webHelperUnit   = "sb-manager-web-helper.service"
	webAgentUnit    = "sb-manager-web-agent.service"
	webRenewUnit    = "sb-manager-web-cert-renew.service"
	webRenewTimer   = "sb-manager-web-cert-renew.timer"
	webServiceName  = "sb-manager-web"
	webHelperName   = "sb-manager-web-helper"
	webAgentName    = "sb-manager-web-agent"
	webRenewJobName = "sb-manager-web-cert-renew"
)

var version = "dev"
var webUninstalled bool

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sb-web: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return menu()
	}
	switch args[0] {
	case "menu":
		return menu()
	case "server", "enable":
		if args[0] == "enable" {
			return serviceAction("start")
		}
		return serve(args[1:])
	case "disable", "restart", "logs":
		return serviceAction(args[0])
	case "agent":
		return runAgent(args[1:])
	case "helper":
		return runHelper(args[1:])
	case "join":
		return join(args[1:])
	case "update":
		return update(args[1:])
	case "status":
		return status(args[1:])
	case "reset-admin-password":
		return resetPassword(args[1:])
	case "init":
		return initialize(args[1:])
	case "uninstall":
		return uninstallWeb(args[1:])
	case "version", "--version", "-V":
		fmt.Printf("sb-manager-web %s\n", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	listen := fs.String("listen", "", "覆盖监听地址")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	cfg.WebVersion = version
	if err := os.MkdirAll(cfg.DataDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.LogDir, 0750); err != nil {
		return err
	}
	if _, err := os.Stat(*configPath); errors.Is(err, os.ErrNotExist) {
		if err := config.Save(*configPath, cfg); err != nil {
			return err
		}
	}
	store, err := storage.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	handler, initialCredential, err := api.New(cfg, store)
	if err != nil {
		return err
	}
	if initialCredential.Password != "" {
		fmt.Printf("首次管理员账号：%s\n首次管理员密码：%s\n请登录后立即修改密码。\n", initialCredential.Username, initialCredential.Password)
	}
	httpServer := &http.Server{Addr: cfg.Listen, Handler: handler.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}
	fmt.Printf("sb-manager-web listening on %s\n", cfg.Listen)
	fmt.Printf("面板访问地址：%s://%s\n", scheme, cfg.Listen)
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			return errors.New("tls enabled but cert_file/key_file are empty")
		}
		tlsConfig, tlsErr := handler.TLSConfig()
		if tlsErr != nil {
			return fmt.Errorf("prepare agent mTLS: %w", tlsErr)
		}
		httpServer.TLSConfig = tlsConfig
	}
	if err := handler.ResumeLocalTasks(); err != nil {
		return fmt.Errorf("resume local tasks: %w", err)
	}
	if cfg.TLS.Enabled {
		err = httpServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	} else {
		err = httpServer.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func initialize(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0750); err != nil {
		return err
	}
	store, err := storage.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	_, credential, err := api.New(cfg, store)
	if err != nil {
		return err
	}
	if credential.Password == "" {
		username, usernameErr := auth.New(store).AdminUsername()
		if usernameErr == nil {
			fmt.Printf("管理员账号：%s\n", username)
		}
		fmt.Println("管理员密码已存在且不会回显；需要重置时运行：sb-web reset-admin-password")
	} else {
		fmt.Printf("首次管理员账号：%s\n首次管理员密码：%s\n请登录后立即修改密码。\n", credential.Username, credential.Password)
	}
	return config.Save(*configPath, cfg)
}

func serviceAction(action string) error {
	return serviceActionFor(action, "sb-manager-web.service", "sb-manager-web")
}

func update(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("更新 sb-manager-web 需要 root，请使用 sudo sb-web update")
	}
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	targetVersion := fs.String("version", "", "目标版本（默认使用最新 Release）")
	installerURL := fs.String("installer-url", os.Getenv("SBM_WEB_INSTALL_URL"), "安装器地址")
	noRestart := fs.Bool("no-restart", false, "更新后不主动重启服务")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetVersion != "" && !runner.ValidVersion(*targetVersion) {
		return errors.New("目标版本格式无效")
	}
	if *installerURL == "" {
		*installerURL = defaultInstallerURL
	}
	if !strings.HasPrefix(*installerURL, "https://") && !strings.HasPrefix(*installerURL, "file://") {
		return errors.New("安装器地址必须使用 HTTPS")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败：%w", err)
	}
	if _, err := os.Stat(*configPath); err != nil {
		return errors.New("未找到 WebUI 配置，无法执行更新")
	}
	tmp, err := os.CreateTemp("", "sb-web-update-*.sh")
	if err != nil {
		return err
	}
	scriptPath := tmp.Name()
	defer os.Remove(scriptPath)
	_ = tmp.Chmod(0700)
	if err := tmp.Close(); err != nil {
		return err
	}
	downloadArgs := []string{"--fail", "--silent", "--show-error", "--location", "--retry", "3", "--retry-delay", "2", "--connect-timeout", "15"}
	if strings.HasPrefix(*installerURL, "https://") {
		downloadArgs = append(downloadArgs, "--proto", "=https", "--tlsv1.2")
	}
	downloadArgs = append(downloadArgs, *installerURL, "-o", scriptPath)
	downloader := exec.Command("curl", downloadArgs...)
	downloader.Stdout, downloader.Stderr, downloader.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := downloader.Run(); err != nil {
		return fmt.Errorf("下载更新安装器失败：%w", err)
	}
	if err := os.Chmod(scriptPath, 0700); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位当前 WebUI 二进制失败：%w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	libDir := filepath.Dir(executable)
	binDir := webBinDir
	if invoked, absErr := filepath.Abs(os.Args[0]); absErr == nil && filepath.Base(invoked) == "sb-web" {
		if info, statErr := os.Lstat(invoked); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			binDir = filepath.Dir(invoked)
		}
	}
	env := append([]string{}, os.Environ()...)
	env = append(env,
		"SBM_WEB_LIB="+libDir,
		"SBM_WEB_BIN="+binDir,
		"SBM_WEB_ETC="+filepath.Dir(*configPath),
		"SBM_WEB_VAR="+cfg.DataDir,
		"SBM_WEB_LOG="+cfg.LogDir,
	)
	cmdArgs := updateInstallerArgs(scriptPath, *targetVersion, *noRestart)
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

func updateInstallerArgs(scriptPath, targetVersion string, noRestart bool) []string {
	args := []string{scriptPath, "--update-only"}
	if targetVersion != "" {
		args = append(args, "--version", targetVersion)
	}
	if noRestart {
		args = append(args, "--no-start")
	}
	return args
}

func serviceActionFor(action, systemdUnit, openRCService string) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		cmd := "systemctl"
		args := []string{action, systemdUnit}
		if action == "start" {
			args = []string{"enable", "--now", systemdUnit}
		}
		if action == "disable" {
			args = []string{"disable", "--now", systemdUnit}
		}
		if action == "restart" {
			args = []string{"restart", systemdUnit}
		}
		if action == "logs" {
			cmd, args = "journalctl", []string{"-u", systemdUnit, "-n", "100", "--no-pager"}
		}
		return runExternal(cmd, args...)
	}
	if action == "logs" {
		return runExternal("tail", "-n", "100", "/var/log/sb-manager-web/server.log")
	}
	return runExternal("rc-service", openRCService, action)
}

func menu() error {
	if !isTerminal(os.Stdin) {
		usage()
		return errors.New("交互面板需要在 SSH/终端中运行；服务请使用 sb-web server")
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("╭──────────────── sb-manager-web ────────────────╮")
		fmt.Println("  1. 查看面板状态与访问地址")
		fmt.Println("  2. 启用并启动面板")
		fmt.Println("  3. 停止并禁用面板")
		fmt.Println("  4. 重启面板")
		fmt.Println("  5. 查看面板日志")
		fmt.Println("  6. 重置管理员密码")
		fmt.Println("  7. 查看面板 TLS/证书配置")
		fmt.Println("  8. 更新 Web 面板")
		fmt.Println("  9. 卸载 Web 面板")
		fmt.Println("  0. 退出")
		fmt.Println("╰───────────────────────────────────────────────╯")
		fmt.Print("请选择 [0-9]: ")
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
			return nil
		}
		if err != nil {
			return err
		}
		switch strings.TrimSpace(line) {
		case "0":
			return nil
		case "1":
			if err := webStatus(); err != nil {
				fmt.Fprintf(os.Stderr, "状态检查失败：%v\n", err)
			}
		case "2":
			if err := serviceAction("start"); err != nil {
				fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
			}
		case "3":
			if err := serviceAction("disable"); err != nil {
				fmt.Fprintf(os.Stderr, "停用失败：%v\n", err)
			}
		case "4":
			if err := serviceAction("restart"); err != nil {
				fmt.Fprintf(os.Stderr, "重启失败：%v\n", err)
			}
		case "5":
			if err := serviceAction("logs"); err != nil {
				fmt.Fprintf(os.Stderr, "日志读取失败：%v\n", err)
			}
		case "6":
			if err := resetPassword(nil); err != nil {
				fmt.Fprintf(os.Stderr, "密码重置失败：%v\n", err)
			}
		case "7":
			if err := webTLSInfo(); err != nil {
				fmt.Fprintf(os.Stderr, "TLS 配置读取失败：%v\n", err)
			}
		case "8":
			if err := update(nil); err != nil {
				fmt.Fprintf(os.Stderr, "更新失败：%v\n", err)
			}
		case "9":
			if err := uninstallMenu(reader); err != nil {
				fmt.Fprintf(os.Stderr, "卸载失败：%v\n", err)
			}
			if webUninstalled {
				return nil
			}
		default:
			fmt.Fprintln(os.Stderr, "选择无效，请输入 0-9。")
		}
	}
}

func uninstallMenu(reader *bufio.Reader) error {
	fmt.Println("\n卸载 Web 面板：")
	fmt.Println("  1. 卸载程序，保留配置、数据库、证书和日志")
	fmt.Println("  2. 完全卸载，删除全部 Web 数据")
	fmt.Println("  0. 返回")
	fmt.Print("请选择 [0-2]: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	switch strings.TrimSpace(choice) {
	case "0":
		return nil
	case "1":
		return uninstallWeb(nil)
	case "2":
		return uninstallWeb([]string{"--purge"})
	default:
		return errors.New("选择无效，请输入 0-2")
	}
}

func isTerminal(file *os.File) bool {
	return isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd())
}

func loadWebConfig() (config.Config, error) {
	return config.Load(defaultConfigPath)
}

func webStatus() error {
	cfg, err := loadWebConfig()
	if err != nil {
		return err
	}
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}
	fmt.Printf("面板监听：%s\n面板地址：%s://%s\n", cfg.Listen, scheme, cfg.Listen)
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		output, commandErr := exec.Command("systemctl", "is-active", webService).CombinedOutput()
		fmt.Printf("服务状态：%s", output)
		if commandErr != nil {
			return commandErr
		}
		return nil
	}
	output, commandErr := exec.Command("rc-service", webServiceName, "status").CombinedOutput()
	fmt.Printf("服务状态：%s", output)
	return commandErr
}

func webTLSInfo() error {
	cfg, err := loadWebConfig()
	if err != nil {
		return err
	}
	if !cfg.TLS.Enabled {
		fmt.Println("面板 HTTPS：未启用")
		fmt.Println("配置方式：安装器 --panel-tls self-signed|acme-http|acme-dns-cloudflare|existing")
		return nil
	}
	fmt.Printf("面板 HTTPS：已启用\n证书：%s\n私钥：%s\n", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if info, statErr := os.Stat(cfg.TLS.CertFile); statErr == nil {
		fmt.Printf("证书文件：%s\n", info.Mode().String())
	} else {
		fmt.Printf("证书文件状态：%v\n", statErr)
	}
	return nil
}

func uninstallWeb(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	purge := fs.Bool("purge", false, "删除配置、数据库、证书、ACME 数据和日志")
	assumeYes := fs.Bool("yes", false, "跳过确认")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("卸载 Web 面板需要 root，请使用 sudo sb-web uninstall")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败（为避免误删已取消）：%w", err)
	}
	if !*assumeYes {
		message := "确认卸载 Web 面板程序？配置、数据库、证书和日志将保留 [y/N]："
		if *purge {
			message = "确认彻底卸载 Web 面板并删除配置、数据库、证书、ACME 数据和日志？请输入 DELETE："
		}
		fmt.Print(message)
		reader := bufio.NewReader(os.Stdin)
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		answer = strings.TrimSpace(answer)
		if (*purge && answer != "DELETE") || (!*purge && !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes")) {
			fmt.Println("已取消卸载。")
			return nil
		}
	}

	if _, statErr := os.Stat("/run/systemd/system"); statErr == nil {
		for _, unit := range []string{webRenewTimer, webAgentUnit, webService, webHelperUnit} {
			_ = exec.Command("systemctl", "disable", "--now", unit).Run()
		}
	} else if _, statErr := os.Stat(filepath.Join(webOpenRCDir, webServiceName)); statErr == nil {
		for _, service := range []string{webServiceName, webHelperName, webAgentName} {
			_ = exec.Command("rc-service", service, "stop").Run()
			_ = exec.Command("rc-update", "del", service, "default").Run()
		}
	}
	for _, path := range []string{
		filepath.Join(webSystemdDir, webService),
		filepath.Join(webSystemdDir, webHelperUnit),
		filepath.Join(webSystemdDir, webAgentUnit),
		filepath.Join(webSystemdDir, webRenewUnit),
		filepath.Join(webSystemdDir, webRenewTimer),
		filepath.Join(webOpenRCDir, webServiceName),
		filepath.Join(webOpenRCDir, webHelperName),
		filepath.Join(webOpenRCDir, webAgentName),
		filepath.Join(webPeriodicDir, "daily", webRenewJobName),
	} {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("删除 %s 失败：%w", path, removeErr)
		}
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	link := filepath.Join(webBinDir, "sb-web")
	if target, readErr := os.Readlink(link); readErr == nil && strings.Contains(target, webLibDir) {
		_ = os.Remove(link)
	}
	if removeErr := os.RemoveAll(webLibDir); removeErr != nil {
		return fmt.Errorf("删除程序目录失败：%w", removeErr)
	}
	if *purge {
		purgePaths := []string{*configPath}
		if filepath.Clean(*configPath) == defaultConfigPath {
			purgePaths = append(purgePaths, filepath.Dir(*configPath))
		}
		for _, path := range []string{cfg.DataDir, cfg.LogDir} {
			cleanPath := filepath.Clean(path)
			if filepath.Base(cleanPath) != "sb-manager-web" {
				return fmt.Errorf("拒绝删除非 Web 专属数据目录：%s；请手动确认后再删除", path)
			}
			purgePaths = append(purgePaths, cleanPath)
		}
		for _, path := range purgePaths {
			if removeErr := os.RemoveAll(path); removeErr != nil {
				return fmt.Errorf("删除数据目录 %s 失败：%w", path, removeErr)
			}
		}
		fmt.Println("Web 面板、配置、数据库、证书、ACME 数据和日志已删除。")
	} else {
		fmt.Printf("Web 面板程序已卸载；配置、数据库、证书和日志保留在 %s、%s、%s。\n", *configPath, cfg.DataDir, cfg.LogDir)
	}
	webUninstalled = true
	return nil
}

func runExternal(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	controller := fs.String("controller", "", "控制端 URL")
	token := fs.String("token", "", "加入令牌")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *controller != "" {
		cfg.Agent.ControllerURL = *controller
	}
	if *token != "" {
		cfg.Agent.EnrollmentToken = *token
	}
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err = a.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func runHelper(args []string) error {
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	socket := fs.String("socket", "", "覆盖 Unix Socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *socket != "" {
		cfg.HelperSocket = *socket
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	webPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位 WebUI 二进制失败：%w", err)
	}
	return helper.Server{Socket: cfg.HelperSocket, Runner: runner.Runner{Path: cfg.SBPath, Timeout: cfg.Tasks.DefaultTimeout}, WebPath: webPath}.Serve(ctx)
}

func join(args []string) error {
	if len(args) < 2 {
		return errors.New("用法：sb-web join CONTROLLER_URL TOKEN [--config PATH]")
	}
	controller, token := args[0], args[1]
	if err := validateControllerURL(controller); err != nil {
		return err
	}
	configPath := defaultConfigPath
	for i := 2; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			configPath = args[i+1]
			i++
		}
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	cfg.Agent.Enabled, cfg.Agent.ControllerURL, cfg.Agent.EnrollmentToken = true, controller, token
	if cfg.Agent.IdentityFile == "" {
		cfg.Agent.IdentityFile = filepath.Join(cfg.DataDir, "agent-identity", "ed25519.json")
	}
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("已保存 Agent 配置：%s\n", configPath)
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	if err := a.Register(context.Background()); err != nil {
		return err
	}
	cfg.Agent.EnrollmentToken = ""
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	if err := serviceActionFor("start", "sb-manager-web-agent.service", "sb-manager-web-agent"); err != nil {
		fmt.Println("Agent 已注册，但未能自动启动服务；请手动运行 sb-web agent 或检查 init 系统。")
		return err
	}
	fmt.Println("Agent 已注册并启动。")
	return nil
}

func validateControllerURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("控制端 URL 无效")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return nil
	}
	return errors.New("远程控制端必须使用 HTTPS（本机 localhost 可使用 HTTP）")
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "配置文件")
	listen := fs.String("listen", "", "覆盖 WebUI 监听地址")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	target, err := statusTarget(cfg)
	if err != nil {
		return err
	}
	transport := &http.Transport{}
	if cfg.TLS.Enabled {
		tlsConfig, tlsErr := statusTLSConfig(cfg)
		if tlsErr != nil {
			return tlsErr
		}
		transport.TLSClientConfig = tlsConfig
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("WebUI 不可用：%w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("WebUI 返回 HTTP %d", response.StatusCode)
	}
	fmt.Printf("sb-manager-web：运行中 (%s)\n", target)
	return nil
}

func statusTarget(cfg config.Config) (string, error) {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return "", fmt.Errorf("WebUI 监听地址无效：%w", err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func statusTLSConfig(cfg config.Config) (*tls.Config, error) {
	if cfg.TLS.CertFile == "" {
		return nil, errors.New("WebUI TLS 证书路径为空")
	}
	certPEM, err := os.ReadFile(cfg.TLS.CertFile)
	if err != nil {
		return nil, fmt.Errorf("读取 WebUI TLS 证书失败：%w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("WebUI TLS 证书链无效")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("WebUI TLS 证书 PEM 无效")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 WebUI TLS 证书失败：%w", err)
	}
	serverName := ""
	if len(certificate.DNSNames) > 0 {
		serverName = certificate.DNSNames[0]
	} else if len(certificate.IPAddresses) > 0 {
		serverName = certificate.IPAddresses[0].String()
	}
	if serverName == "" {
		return nil, errors.New("WebUI TLS 证书缺少 DNS/IP SAN")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}, nil
}

func resetPassword(args []string) error {
	if len(args) > 2 {
		return errors.New("用法：sb-web reset-admin-password [用户名] [新密码]")
	}
	cfg, err := config.Load(defaultConfigPath)
	if err != nil {
		return err
	}
	store, err := storage.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	manager := auth.New(store)
	username, err := manager.AdminUsername()
	if err != nil {
		return err
	}
	password := ""
	if len(args) == 2 {
		username, password = args[0], args[1]
	} else if len(args) == 1 {
		password = args[0]
	} else {
		password, err = auth.RandomToken(18)
		if err != nil {
			return err
		}
	}
	if err := manager.SetPassword(username, password); err != nil {
		return err
	}
	fmt.Printf("账号 %s 的新管理员密码：%s\n", username, password)
	return nil
}

func usage() {
	fmt.Print(`sb-manager-web：Go WebUI 控制层

用法：
  sb-web                              打开交互管理面板
  sb-web menu                         打开交互管理面板
  sb-web server [--config PATH] [--listen HOST:PORT]
  sb-web enable                         启用并启动 WebUI 服务
  sb-web disable|restart|logs           服务管理
  sb-web agent [--config PATH]
  sb-web join CONTROLLER_URL TOKEN
  sb-web update [--version VERSION] [--no-restart]
  sb-web status [--config PATH] [--listen HOST:PORT]
  sb-web init [--config PATH]           初始化配置和管理员账号
  sb-web reset-admin-password [USERNAME] [PASSWORD]
  sb-web uninstall [--purge] [--yes]   卸载 Web（默认保留数据）
  sb-web version
`)
}
