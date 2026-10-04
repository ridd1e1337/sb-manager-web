package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/runner"
)

func TestUnixHelperExecutesAllowlistedAction(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "sb")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '{\"enabled\":true}'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "run", "helper.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := Server{Socket: socket, Runner: runner.Runner{Path: binary, Timeout: time.Second}}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(ctx) }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	result, err := (Client{Socket: socket, Timeout: time.Second}).Run(context.Background(), "bbr.status", nil)
	if err != nil || result.Stdout == "" {
		t.Fatalf("helper call failed: result=%#v err=%v", result, err)
	}
	cancel()
	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Fatal("helper did not shut down")
	}
}

func TestUnixHelperRunsWebUpdateSeparately(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "updated")
	webBinary := filepath.Join(dir, "sb-web")
	script := "#!/bin/sh\nprintf '%s\\n' updated >" + marker + "\n"
	if err := os.WriteFile(webBinary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "run", "helper.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := Server{Socket: socket, WebPath: webBinary, Runner: runner.Runner{Path: webBinary, Timeout: time.Second}}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(ctx) }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := (Client{Socket: socket, Timeout: time.Second}).Run(context.Background(), "web.update", nil); err != nil {
		t.Fatalf("web update helper call failed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("web updater was not executed: %v", err)
	}
	cancel()
	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Fatal("helper did not shut down")
	}
}
