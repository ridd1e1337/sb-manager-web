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

func TestAirportURLs(t *testing.T) {
	for _, value := range []string{"https://panel.example.com/shop/admin/", "javascript:alert(1)", "http://panel.example.com", "https://user:pass@panel.example.com", "https://panel.example.com/?token=secret"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			cfg := Defaults()
			cfg.Airport.StoreAdminURL = value
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			valid := value == "https://panel.example.com/shop/admin/"
			if (err == nil) != valid {
				t.Fatalf("URL %q: %v", value, err)
			}
		})
	}
}
