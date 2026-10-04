package tests

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/agent"
	"github.com/ridd1e1337/sb-manager-web/internal/api"
	"github.com/ridd1e1337/sb-manager-web/internal/auth"
	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func TestAgentEnrollmentHeartbeatAndTask(t *testing.T) {
	dir := t.TempDir()
	fakeSB := filepath.Join(dir, "sb")
	content := `#!/bin/sh
case "$*" in
  *"status"*) printf '%s\n' '{"services":{"sing_box":{"active":true}},"nodes":[]}' ;;
  *"capabilities"*) printf '%s\n' '{"version":"1.14.0-rc.2","tags":[]}' ;;
  version) printf '%s\n' 'sb-manager 0.1.0-alpha.27' ;;
  *"bbr enable"*) printf '%s\n' 'enabled' ;;
  *) printf '%s\n' '{}' ;;
esac
`
	if err := os.WriteFile(fakeSB, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	controllerConfig := config.Defaults()
	controllerConfig.SBPath, controllerConfig.DataDir = fakeSB, filepath.Join(dir, "controller")
	controllerConfig.Database, controllerConfig.Tasks.DefaultTimeout = filepath.Join(dir, "controller.db"), time.Second
	store, err := storage.Open(controllerConfig.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, _, err := api.New(controllerConfig, store)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler.Handler())
	defer server.Close()
	token, _ := auth.RandomToken(24)
	hash := auth.HashEnrollmentToken(token)
	if err := store.PutEnrollment(hash, types.EnrollmentToken{Hash: hash, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	agentConfig := config.Defaults()
	agentConfig.SBPath, agentConfig.DataDir = fakeSB, filepath.Join(dir, "agent")
	agentConfig.Database = filepath.Join(dir, "agent.db")
	agentConfig.Agent.ControllerURL, agentConfig.Agent.EnrollmentToken = server.URL, token
	agentConfig.Agent.IdentityFile = filepath.Join(dir, "agent", "identity.json")
	agentConfig.Tasks.DefaultTimeout = time.Second
	a, err := agent.New(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	servers, err := store.ListServers()
	if err != nil {
		t.Fatal(err)
	}
	var remoteID string
	for _, candidate := range servers {
		if candidate.ID != types.ServerLocal {
			remoteID = candidate.ID
		}
	}
	if remoteID == "" {
		t.Fatal("agent registration did not create a remote server")
	}
	task := types.Task{ID: "task_agent_test", ServerID: remoteID, Action: "bbr.enable", Status: types.TaskPending, CreatedAt: time.Now().UTC()}
	if err := store.PutTask(task); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, err := store.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != types.TaskSuccess || completed.Output == "" {
		t.Fatalf("unexpected task result: %#v", completed)
	}
	if _, err := agent.New(agentConfig); err != nil {
		t.Fatal(err)
	}
	// The enrollment is consumed and cannot create another identity.
	secondConfig := agentConfig
	secondConfig.Agent.IdentityFile = filepath.Join(dir, "agent2", "identity.json")
	second, err := agent.New(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Register(context.Background()); err == nil {
		t.Fatal("consumed enrollment token was accepted twice")
	}
}
