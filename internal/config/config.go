package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type TLSConfig struct {
	Enabled          bool   `json:"enabled"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	ClientCAFile     string `json:"client_ca_file,omitempty"`
	ClientCAKeyFile  string `json:"client_ca_key_file,omitempty"`
	RequireAgentMTLS bool   `json:"require_agent_mtls"`
}

type AgentConfig struct {
	Enabled           bool   `json:"enabled"`
	ControllerURL     string `json:"controller_url"`
	EnrollmentToken   string `json:"enrollment_token,omitempty"`
	IdentityFile      string `json:"identity_file"`
	HeartbeatInterval string `json:"heartbeat_interval"`
}

type TaskConfig struct {
	DefaultTimeout time.Duration `json:"-"`
	TimeoutText    string        `json:"default_timeout"`
	Concurrency    int           `json:"batch_concurrency"`
	FailureStopPct int           `json:"failure_stop_percent"`
}

type Config struct {
	ConfigPath   string      `json:"-"`
	WebVersion   string      `json:"-"`
	Listen       string      `json:"listen"`
	SBPath       string      `json:"sb_path"`
	StateFile    string      `json:"state_file"`
	DataDir      string      `json:"data_dir"`
	Database     string      `json:"database"`
	LogDir       string      `json:"log_dir"`
	BackupDir    string      `json:"backup_dir"`
	HelperSocket string      `json:"helper_socket"`
	TLS          TLSConfig   `json:"tls"`
	Agent        AgentConfig `json:"agent"`
	Tasks        TaskConfig  `json:"tasks"`
}

func Defaults() Config {
	return Config{
		Listen:       "127.0.0.1:9091",
		SBPath:       "/usr/local/bin/sb",
		StateFile:    "/etc/sb-manager/state.json",
		DataDir:      "/var/lib/sb-manager-web",
		Database:     "/var/lib/sb-manager-web/web.db",
		LogDir:       "/var/log/sb-manager-web",
		BackupDir:    "/var/lib/sb-manager-web/backups",
		HelperSocket: "/run/sb-manager-web/helper.sock",
		Agent: AgentConfig{
			IdentityFile:      "/var/lib/sb-manager-web/agent-identity/ed25519.key",
			HeartbeatInterval: "30s",
		},
		Tasks: TaskConfig{TimeoutText: "10m", Concurrency: 1, FailureStopPct: 25},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		path = "/etc/sb-manager-web/config.json"
	}
	cfg.ConfigPath = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg.Tasks.DefaultTimeout = 10 * time.Minute
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.Tasks.DefaultTimeout = 10 * time.Minute
	if cfg.Tasks.TimeoutText != "" {
		parsed, err := time.ParseDuration(cfg.Tasks.TimeoutText)
		if err != nil || parsed <= 0 {
			return Config{}, fmt.Errorf("invalid tasks.default_timeout: %q", cfg.Tasks.TimeoutText)
		}
		cfg.Tasks.DefaultTimeout = parsed
	}
	if cfg.Listen == "" || cfg.SBPath == "" || cfg.StateFile == "" || cfg.DataDir == "" || cfg.Database == "" || cfg.BackupDir == "" {
		return Config{}, errors.New("listen, sb_path, state_file, data_dir, database and backup_dir are required")
	}
	if cfg.Tasks.Concurrency < 1 || cfg.Tasks.Concurrency > 32 {
		return Config{}, errors.New("tasks.batch_concurrency must be between 1 and 32")
	}
	if cfg.TLS.RequireAgentMTLS && !cfg.TLS.Enabled {
		return Config{}, errors.New("tls.require_agent_mtls requires tls.enabled")
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if path == "" {
		return errors.New("config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
