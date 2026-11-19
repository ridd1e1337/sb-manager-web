package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/agent"
	"github.com/ridd1e1337/sb-manager-web/internal/api"
	"github.com/ridd1e1337/sb-manager-web/internal/auth"
	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func TestOperationsRemotePrivatePayloadAndPermissions(t *testing.T) {
	dir := t.TempDir()
	sb := filepath.Join(dir, "sb")
	script := `#!/bin/sh
case "$*" in
  version) printf '%s\n' 'sb-manager 0.1.0-alpha.34';;
  *"core capabilities"*) printf '%s\n' '{"version":"1.14.0"}';;
  *"node list"*) printf '%s\n' '[]';;
  *"substore source add"*) printf '%s\n' "$*";;
  *"subscription create"*) printf '%s\n' '本机 URL：http://127.0.0.1:9080/sub/private-result-fixture';;
  *) printf '%s\n' '{}';;
esac
`
	if err := os.WriteFile(sb, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.SBPath = sb
	cfg.HelperSocket = ""
	cfg.DataDir = dir
	cfg.Database = filepath.Join(dir, "web.db")
	cfg.Tasks.DefaultTimeout = time.Second
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	controller, owner, err := api.New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(controller.Handler())
	defer httpServer.Close()
	manager := auth.New(store)
	ownerSession, err := manager.NewSession(owner.Username)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "operator"} {
		if err := manager.CreateUser(role, "test-only-password-83921", role); err != nil {
			t.Fatal(err)
		}
	}
	viewer, _ := manager.NewSession("viewer")
	operator, _ := manager.NewSession("operator")
	request := func(session types.Session, method, path string, payload any, csrf bool) (int, []byte) {
		t.Helper()
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(method, httpServer.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sbweb_session", Value: session.ID})
		if csrf {
			req.Header.Set("X-CSRF-Token", session.CSRF)
		}
		response, err := httpServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, data
	}
	invoke := func(session types.Session, serverID, action string, args map[string]any) (int, types.Task) {
		t.Helper()
		status, data := request(session, "POST", "/api/v1/operations", map[string]any{"server_id": serverID, "action": action, "args": args}, true)
		var task types.Task
		_ = json.Unmarshal(data, &task)
		return status, task
	}
	if status, _ := request(ownerSession, "POST", "/api/v1/operations", map[string]any{"action": "tcp.status"}, false); status != 403 {
		t.Fatal("operation bypasses CSRF")
	}
	if status, _ := invoke(viewer, "local", "tcp.enable", map[string]any{"bandwidth": 100.0, "rtt": 20.0}); status != 403 {
		t.Fatal("viewer can mutate TCP")
	}
	if status, _ := invoke(operator, "local", "substore.source.add", map[string]any{"name": "edge", "url": "https://source.example/sub/private-input-fixture"}); status != 403 {
		t.Fatal("operator can submit private credentials")
	}
	for _, path := range []string{"/api/v1/batch/actions", "/api/v1/batch/preflight"} {
		status, _ := request(operator, "POST", path, map[string]any{"server_ids": []string{"local"}, "action": "deps.install", "args": map[string]any{"feature": "substore"}}, true)
		if status != 403 {
			t.Fatal("batch bypasses admin role")
		}
	}
	if status, _ := invoke(viewer, "local", "tcp.status", nil); status != 202 {
		t.Fatal("viewer cannot read state through operation transport")
	}
	// Authenticate a real Agent with enrollment and signed polling, then exercise
	// private arguments in transit and encrypted result consumption end to end.
	token, _ := auth.RandomToken(24)
	hash := auth.HashEnrollmentToken(token)
	if err := store.PutEnrollment(hash, types.EnrollmentToken{Hash: hash, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "agent-state.json")
	_ = os.WriteFile(state, []byte(`{"schema_version":2,"nodes":[]}`), 0600)
	agentCfg := cfg
	agentCfg.StateFile = state
	agentCfg.Agent.ControllerURL = httpServer.URL
	agentCfg.Agent.EnrollmentToken = token
	agentCfg.Agent.IdentityFile = filepath.Join(dir, "identity.json")
	remote, err := agent.New(agentCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	servers, _ := store.ListServers()
	serverID := ""
	for _, server := range servers {
		if server.ID != "local" {
			serverID = server.ID
		}
	}
	if serverID == "" {
		t.Fatal("Agent not registered")
	}
	status, task := invoke(ownerSession, serverID, "substore.source.add", map[string]any{"name": "edge", "url": "https://source.example/sub/private-input-fixture"})
	if status != 202 || !task.Private || task.Args != nil {
		t.Fatalf("private task not accepted safely: status=%d", status)
	}
	if err = remote.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, err := store.GetTask(task.ID)
	if err != nil || completed.Status != types.TaskSuccess {
		t.Fatalf("remote operation failed: %#v %v", completed, err)
	}
	if strings.Contains(completed.Output, "private-input-fixture") || completed.Args != nil {
		t.Fatal("private credentials leaked to task record")
	}
	status, data := request(ownerSession, "GET", "/api/v1/tasks", nil, false)
	if status != 200 || bytes.Contains(data, []byte("private-input-fixture")) {
		t.Fatal("task list leaked private input")
	}
	path := "/api/v1/tasks/" + task.ID + "/private-result"
	if status, _ = request(operator, "POST", path, map[string]any{}, true); status != 403 {
		t.Fatal("operator can read private output")
	}
	status, data = request(ownerSession, "POST", path, map[string]any{}, true)
	if status != 200 || !bytes.Contains(data, []byte("private-input-fixture")) {
		t.Fatal("Agent did not receive original private args")
	}
	if status, _ = request(ownerSession, "POST", path, map[string]any{}, true); status != 410 {
		t.Fatal("private output is not single-use")
	}
	// A privileged direct action must use the same role gate as the new route.
	if status, _ = request(operator, "POST", "/api/v1/servers/local/actions", map[string]any{"action": "manager.update"}, true); status != 403 {
		t.Fatal("legacy action route bypasses admin role")
	}
	old, _ := store.GetServer(serverID)
	old.AgentFeatures = []string{"self_update_v1"}
	_ = store.PutServer(old)
	if status, _ = invoke(ownerSession, serverID, "tcp.status", nil); status != 409 {
		t.Fatal("old Agent accepted unsupported operation")
	}
}
