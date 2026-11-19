package config

import (
	"path/filepath"
	"testing"
)

func TestLoadTracksConfigPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigPath != path {
		t.Fatalf("config path=%q, want %q", cfg.ConfigPath, path)
	}
}
