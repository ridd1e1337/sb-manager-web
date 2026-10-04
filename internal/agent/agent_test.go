package agent

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/api"
	"github.com/ridd1e1337/sb-manager-web/internal/auth"
	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/runner"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func TestStateSnapshotDigestAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2,"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	digest, schema, err := stateSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 || schema != 2 {
		t.Fatalf("unexpected snapshot: digest=%q schema=%d", digest, schema)
	}
	if _, _, err := stateSnapshot(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing state file was accepted")
	}
}

func TestControllerURLRequiresTLSRemotely(t *testing.T) {
	for _, test := range []struct {
		url string
		ok  bool
	}{
		{"https://panel.example.com/", true},
		{"http://127.0.0.1:9091", true},
		{"http://panel.example.com", false},
		{"https://panel.example.com/path", false},
	} {
		if got := validateControllerURL(test.url) == nil; got != test.ok {
			t.Fatalf("validateControllerURL(%q)=%v, want %v", test.url, got, test.ok)
		}
	}
}

func TestSelfUpdateArgsDefersServiceRestart(t *testing.T) {
	got := strings.Join(selfUpdateArgs("/etc/custom.json", "2.0.0"), " ")
	if got != "update --config /etc/custom.json --version 2.0.0 --no-restart" {
		t.Fatalf("unexpected self-update args: %s", got)
	}
}

func TestRegisterHeartbeatTaskAndDriftProtection(t *testing.T) {
	dir := t.TempDir()
	fakeSB := filepath.Join(dir, "sb")
	content := `#!/bin/sh
case "$*" in
  *"status"*) printf '%s\n' '{"services":{"sing_box":{"active":true}},"nodes":[]}' ;;
  *"capabilities"*) printf '%s\n' '{"version":"1.14.0","tags":[]}' ;;
  *"node list"*) printf '%s\n' '{"nodes":[]}' ;;
  version) printf '%s\n' 'sb-manager 1.0.0' ;;
  *"bbr enable"*) printf '%s\n' 'enabled' ;;
  *) printf '%s\n' '{}' ;;
esac
`
	if err := os.WriteFile(fakeSB, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	controllerConfig := config.Defaults()
	controllerConfig.SBPath = fakeSB
	controllerConfig.DataDir = filepath.Join(dir, "controller")
	controllerConfig.Database = filepath.Join(dir, "controller.db")
	controllerConfig.Tasks.DefaultTimeout = time.Second
	store, err := storage.Open(controllerConfig.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, _, err := api.New(controllerConfig, store)
	if err != nil {
		t.Fatal(err)
	}
	controller := httptest.NewServer(handler.Handler())
	defer controller.Close()
	token, err := auth.RandomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	hash := auth.HashEnrollmentToken(token)
	if err := store.PutEnrollment(hash, types.EnrollmentToken{Hash: hash, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(dir, "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"schema_version":2,"nodes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	agentConfig := config.Defaults()
	agentConfig.SBPath = fakeSB
	agentConfig.StateFile = stateFile
	agentConfig.DataDir = filepath.Join(dir, "agent")
	agentConfig.Agent.ControllerURL = controller.URL
	agentConfig.Agent.EnrollmentToken = token
	agentConfig.Agent.IdentityFile = filepath.Join(dir, "agent", "identity.json")
	agentConfig.Tasks.DefaultTimeout = time.Second
	value, err := New(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := value.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	servers, err := store.ListServers()
	if err != nil {
		t.Fatal(err)
	}
	remoteID := ""
	for _, server := range servers {
		if server.ID != types.ServerLocal {
			remoteID = server.ID
		}
	}
	if remoteID == "" {
		t.Fatal("registration did not create a remote server")
	}
	digest, _, err := stateSnapshot(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	successTask := types.Task{ID: "task_agent_success", ServerID: remoteID, Action: "bbr.enable", Status: types.TaskPending, CreatedAt: time.Now().UTC(), ExpectedStateDigest: digest}
	if err := store.PutTask(successTask); err != nil {
		t.Fatal(err)
	}
	if err := value.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	updatedServer, err := store.GetServer(remoteID)
	if err != nil || len(updatedServer.AgentFeatures) != 1 || updatedServer.AgentFeatures[0] != "self_update_v1" {
		t.Fatalf("Agent features were not reported: %#v err=%v", updatedServer.AgentFeatures, err)
	}
	completed, err := store.GetTask(successTask.ID)
	if err != nil || completed.Status != types.TaskSuccess || completed.Output == "" {
		t.Fatalf("completed task=%#v err=%v", completed, err)
	}
	driftTask := types.Task{ID: "task_agent_drift", ServerID: remoteID, Action: "bbr.enable", Status: types.TaskPending, CreatedAt: time.Now().UTC(), ExpectedStateDigest: "stale-digest"}
	if err := store.PutTask(driftTask); err != nil {
		t.Fatal(err)
	}
	if err := value.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	drifted, err := store.GetTask(driftTask.ID)
	if err != nil || drifted.Status != types.TaskFailed || !strings.Contains(drifted.Error, "state drift detected") {
		t.Fatalf("drift task=%#v err=%v", drifted, err)
	}
	confirmTask := types.Task{ID: "task_agent_confirm", ServerID: remoteID, Action: "agent.update", Args: map[string]any{"version": Version}, Status: types.TaskPending, CreatedAt: time.Now().UTC()}
	if err := store.PutTask(confirmTask); err != nil {
		t.Fatal(err)
	}
	if err := value.heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	confirmed, err := store.GetTask(confirmTask.ID)
	if err != nil || confirmed.Status != types.TaskSuccess || !strings.Contains(confirmed.Output, Version) {
		t.Fatalf("heartbeat did not confirm update: %#v err=%v", confirmed, err)
	}
	updatedVersion := "9.9.9"
	calledVersion := ""
	value.selfUpdate = func(_ context.Context, version string) (runner.Result, error) {
		calledVersion = version
		return runner.Result{Stdout: "Agent update installed"}, nil
	}
	updateTask := types.Task{ID: "task_agent_update", ServerID: remoteID, Action: "agent.update", Args: map[string]any{"version": updatedVersion}, Status: types.TaskPending, CreatedAt: time.Now().UTC()}
	if err := store.PutTask(updateTask); err != nil {
		t.Fatal(err)
	}
	if err := value.poll(context.Background()); !errors.Is(err, errAgentRestart) {
		t.Fatalf("Agent update did not request restart: %v", err)
	}
	updatedTask, err := store.GetTask(updateTask.ID)
	if err != nil || updatedTask.Status != types.TaskSuccess || calledVersion != updatedVersion {
		t.Fatalf("update task=%#v calledVersion=%q err=%v", updatedTask, calledVersion, err)
	}
}
