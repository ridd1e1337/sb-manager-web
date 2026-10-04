package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ridd1e1337/sb-manager-web/internal/config"
)

func TestUpdateInstallerArgsCanDeferRestart(t *testing.T) {
	want := []string{"/tmp/install.sh", "--update-only", "--version", "1.2.3", "--no-start"}
	if got := updateInstallerArgs("/tmp/install.sh", "1.2.3", true); !reflect.DeepEqual(got, want) {
		t.Fatalf("update args=%v, want %v", got, want)
	}
}

func TestStatusTargetUsesLoopbackForWildcardTLS(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listen = "0.0.0.0:9091"
	cfg.TLS.Enabled = true
	target, err := statusTarget(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if target != "https://127.0.0.1:9091/healthz" {
		t.Fatalf("unexpected status target: %s", target)
	}
}

func TestStatusSupportsLocalHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.Defaults()
	cfg.Listen = strings.TrimPrefix(server.URL, "https://")
	cfg.TLS.Enabled = true
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.TLS.CertFile = certPath
	path := filepath.Join(dir, "config.json")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := status([]string{"--config", path}); err != nil {
		t.Fatalf("HTTPS status probe failed: %v", err)
	}
}
