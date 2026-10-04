package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func fakeSB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sb")
	content := `#!/bin/sh
case "$*" in
  *"realm status"*) printf '%s\n' '{"enabled":false,"listen":"::","port":9443}' ;;
  *"status"*) printf '%s\n' '{"services":{"sing_box":{"active":true}},"nodes":[]}' ;;
  *"node list"*) printf '%s\n' '{"nodes":[]}' ;;
  *"capabilities"*) printf '%s\n' '{"version":"1.14.0-rc.2","tags":[]}' ;;
  *"bbr status"*) printf '%s\n' '{"enabled":false}' ;;
  *"hy2 buffer status"*) printf '%s\n' '{"enabled":false}' ;;
  version) printf '%s\n' 'sb-manager 0.1.0-alpha.27' ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoginStatusAndAction(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database, cfg.SBPath = dir, filepath.Join(dir, "web.db"), fakeSB(t)
	cfg.Tasks.DefaultTimeout = time.Second
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, initial, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	form := url.Values{"username": {initial.Username}, "password": {initial.Password}}
	login, err := client.PostForm(server.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status: %d", login.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.Jar.SetCookies(mustURL(server.URL), login.Cookies())
	csrf := ""
	for _, cookie := range login.Cookies() {
		if cookie.Name == csrfCookie {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("login did not issue csrf cookie")
	}
	response, err := client.Get(server.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(data), `"sing_box"`) {
		t.Fatalf("status response: %d %s", response.StatusCode, data)
	}
	metricsResponse, err := client.Get(server.URL + "/api/v1/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsData, _ := io.ReadAll(metricsResponse.Body)
	metricsResponse.Body.Close()
	if metricsResponse.StatusCode != http.StatusOK || !strings.Contains(string(metricsData), "sb_manager_up 1") {
		t.Fatalf("metrics response: %d %s", metricsResponse.StatusCode, metricsData)
	}
	realmResponse, err := client.Get(server.URL + "/api/v1/realm")
	if err != nil {
		t.Fatal(err)
	}
	var realm map[string]any
	if err := json.NewDecoder(realmResponse.Body).Decode(&realm); err != nil {
		t.Fatal(err)
	}
	realmResponse.Body.Close()
	if realmResponse.StatusCode != http.StatusOK || realm["enabled"] != false {
		t.Fatalf("realm response: %d %#v", realmResponse.StatusCode, realm)
	}
	for _, page := range []string{"/", "/servers/local", "/servers/local/nodes/demo", "/settings/users", "/operations"} {
		pageResponse, pageErr := client.Get(server.URL + page)
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		pageBody, _ := io.ReadAll(pageResponse.Body)
		pageResponse.Body.Close()
		if pageResponse.StatusCode != http.StatusOK || len(pageBody) == 0 {
			t.Fatalf("page %s: status=%d body=%d", page, pageResponse.StatusCode, len(pageBody))
		}
	}
	body := strings.NewReader(`{"action":"bbr.enable","idempotency_key":"test-action-1"}`)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/servers/local/actions", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	actionResponse, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var task map[string]any
	if err := json.NewDecoder(actionResponse.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	actionResponse.Body.Close()
	if actionResponse.StatusCode != http.StatusAccepted || task["id"] == nil {
		t.Fatalf("action response: %d %#v", actionResponse.StatusCode, task)
	}
	userBody := strings.NewReader(`{"username":"operator","password":"correct horse battery staple","role":"operator"}`)
	userRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/users", userBody)
	userRequest.Header.Set("Content-Type", "application/json")
	userRequest.Header.Set("X-CSRF-Token", csrf)
	userResponse, err := client.Do(userRequest)
	if err != nil {
		t.Fatal(err)
	}
	userResponse.Body.Close()
	if userResponse.StatusCode != http.StatusCreated {
		t.Fatalf("user create status: %d", userResponse.StatusCode)
	}
	roleBody := strings.NewReader(`{"role":"viewer"}`)
	roleRequest, _ := http.NewRequest(http.MethodPatch, server.URL+"/api/v1/users/operator", roleBody)
	roleRequest.Header.Set("Content-Type", "application/json")
	roleRequest.Header.Set("X-CSRF-Token", csrf)
	roleResponse, err := client.Do(roleRequest)
	if err != nil {
		t.Fatal(err)
	}
	roleResponse.Body.Close()
	if roleResponse.StatusCode != http.StatusOK {
		t.Fatalf("role update status: %d", roleResponse.StatusCode)
	}
	deleteRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/users/operator", nil)
	deleteRequest.Header.Set("X-CSRF-Token", csrf)
	deleteResponse, err := client.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusOK {
		t.Fatalf("user delete status: %d", deleteResponse.StatusCode)
	}
	enrollmentRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/enrollment", strings.NewReader("{}"))
	enrollmentRequest.Header.Set("Content-Type", "application/json")
	enrollmentRequest.Header.Set("X-CSRF-Token", csrf)
	enrollmentResponse, err := client.Do(enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment map[string]any
	if err := json.NewDecoder(enrollmentResponse.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	enrollmentResponse.Body.Close()
	command, _ := enrollment["join_command"].(string)
	if enrollmentResponse.StatusCode != http.StatusCreated || !strings.Contains(command, "install.sh") || !strings.Contains(command, "--agent") {
		t.Fatalf("enrollment command is not one-step: %d %q", enrollmentResponse.StatusCode, command)
	}
	tokenRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/tokens", strings.NewReader(`{"name":"metrics","role":"viewer"}`))
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenRequest.Header.Set("X-CSRF-Token", csrf)
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	var tokenValue map[string]any
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenValue); err != nil {
		t.Fatal(err)
	}
	tokenResponse.Body.Close()
	rawToken, _ := tokenValue["token"].(string)
	metricsRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/metrics", nil)
	metricsRequest.Header.Set("Authorization", "Bearer "+rawToken)
	metricsTokenResponse, err := client.Do(metricsRequest)
	if err != nil {
		t.Fatal(err)
	}
	metricsTokenResponse.Body.Close()
	if metricsTokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("metrics token status: %d", metricsTokenResponse.StatusCode)
	}
}

func TestResumeLocalTasksAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database, cfg.SBPath = dir, filepath.Join(dir, "web.db"), fakeSB(t)
	cfg.Tasks.DefaultTimeout = time.Second
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	task := types.Task{ID: "task_restart", ServerID: types.ServerLocal, Action: "bbr.enable", Status: types.TaskRunning, CreatedAt: time.Now().UTC()}
	if err := store.PutTask(task); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recovered, err := store.GetTask(task.ID)
	if err != nil || recovered.Status != types.TaskPending {
		t.Fatalf("recovered task=%#v err=%v", recovered, err)
	}
	handler, _, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.ResumeLocalTasks(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		completed, getErr := store.GetTask(task.ID)
		if getErr == nil && completed.Status == types.TaskSuccess {
			if completed.StartedAt == nil || completed.FinishedAt == nil {
				t.Fatalf("task timestamps were not recorded: %#v", completed)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	final, _ := store.GetTask(task.ID)
	t.Fatalf("recovered local task did not finish: %#v", final)
}

func TestAuditUsesAuthenticatedUsername(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database, cfg.SBPath = dir, filepath.Join(dir, "web.db"), fakeSB(t)
	cfg.Tasks.DefaultTimeout = time.Second
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, initial, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler.Handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	login, err := client.PostForm(server.URL+"/login", url.Values{"username": {initial.Username}, "password": {initial.Password}})
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.Jar.SetCookies(mustURL(server.URL), login.Cookies())
	csrf := ""
	for _, cookie := range login.Cookies() {
		if cookie.Name == csrfCookie {
			csrf = cookie.Value
		}
	}
	if err := store.PutServer(types.Server{ID: "srv_audit", Name: "audit", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) *http.Response {
		t.Helper()
		request, requestErr := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		response, requestErr := client.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	actionResponse := do(http.MethodPost, "/api/v1/servers/srv_audit/actions", `{"action":"bbr.enable","idempotency_key":"audit-action"}`)
	var task types.Task
	if err := json.NewDecoder(actionResponse.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	actionResponse.Body.Close()
	if actionResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("action status: %d", actionResponse.StatusCode)
	}
	cancelResponse := do(http.MethodPost, "/api/v1/tasks/"+task.ID+"/cancel", `{}`)
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel status: %d", cancelResponse.StatusCode)
	}
	retryRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/tasks/"+task.ID+"/retry", strings.NewReader(`{}`))
	retryRequest.Header.Set("Content-Type", "application/json")
	retryRequest.Header.Set("X-CSRF-Token", csrf)
	retryRequest.Header.Set("Idempotency-Key", "audit-retry")
	retryResponse, err := client.Do(retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	retryResponse.Body.Close()
	if retryResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("retry status: %d", retryResponse.StatusCode)
	}
	batchResponse := do(http.MethodPost, "/api/v1/batch/actions", `{"server_ids":["srv_audit"],"action":"health.check","args":{},"strategy":"all"}`)
	batchResponse.Body.Close()
	if batchResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("batch status: %d", batchResponse.StatusCode)
	}
	revokeResponse := do(http.MethodDelete, "/api/v1/servers/srv_audit", "")
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK {
		t.Fatalf("revoke status: %d", revokeResponse.StatusCode)
	}
	events, err := store.ListAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"bbr.enable": false, "task.cancel": false, "task.retry": false, "health.check": false, "server.revoke": false}
	for _, event := range events {
		if _, ok := wanted[event.Action]; !ok {
			continue
		}
		if event.Actor != initial.Username {
			t.Fatalf("audit %s actor=%q, want %q", event.Action, event.Actor, initial.Username)
		}
		wanted[event.Action] = true
	}
	for action, found := range wanted {
		if !found {
			t.Fatalf("missing audit event for %s: %#v", action, events)
		}
	}
}

func TestAgentUpdateQueueValidation(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database, cfg.SBPath = dir, filepath.Join(dir, "web.db"), fakeSB(t)
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, initial, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	adminSession := types.Session{Username: initial.Username}
	if err := handler.auth.CreateUser("operator", "correct horse battery staple", "operator"); err != nil {
		t.Fatal(err)
	}
	operatorSession := types.Session{Username: "operator"}
	supported := types.Server{ID: "srv_supported", Name: "supported", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "1.0.0", AgentFeatures: []string{"self_update_v1"}, StateDigest: "state-digest"}
	legacy := types.Server{ID: "srv_legacy", Name: "legacy", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "1.0.0"}
	current := types.Server{ID: "srv_current", Name: "current", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "2.0.0", AgentFeatures: []string{"self_update_v1"}}
	for _, server := range []types.Server{supported, legacy, current} {
		if err := store.PutServer(server); err != nil {
			t.Fatal(err)
		}
	}
	recorder := httptest.NewRecorder()
	handler.enqueueAction(recorder, supported.ID, actionRequest{Action: "agent.update", Args: map[string]any{"version": "2.0.0"}, IdempotencyKey: "agent-update-test"}, adminSession)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("supported update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var task types.Task
	if err := json.NewDecoder(recorder.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	if task.Action != "agent.update" || task.ExpectedStateDigest != "" || task.Args["version"] != "2.0.0" {
		t.Fatalf("unexpected Agent update task: %#v", task)
	}
	taskRequest := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+task.ID+"/cancel", strings.NewReader(`{}`))
	taskRecorder := httptest.NewRecorder()
	handler.taskAPI(taskRecorder, taskRequest, operatorSession)
	if taskRecorder.Code != http.StatusForbidden {
		t.Fatalf("operator managed Agent update task: status=%d body=%s", taskRecorder.Code, taskRecorder.Body.String())
	}
	for _, test := range []struct {
		name    string
		server  string
		session types.Session
		args    map[string]any
		status  int
	}{
		{"operator", supported.ID, operatorSession, map[string]any{"version": "2.0.0"}, http.StatusForbidden},
		{"legacy", legacy.ID, adminSession, map[string]any{"version": "2.0.0"}, http.StatusConflict},
		{"current", current.ID, adminSession, map[string]any{"version": "2.0.0"}, http.StatusConflict},
		{"invalid", supported.ID, adminSession, map[string]any{"version": "bad version"}, http.StatusBadRequest},
		{"local", types.ServerLocal, adminSession, map[string]any{"version": "2.0.0"}, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.enqueueAction(recorder, test.server, actionRequest{Action: "agent.update", Args: test.args, IdempotencyKey: "agent-update-" + test.name}, test.session)
			if recorder.Code != test.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestAgentUpdateBatchPreflight(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database, cfg.SBPath = dir, filepath.Join(dir, "web.db"), fakeSB(t)
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, initial, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []types.Server{
		{ID: "srv_old", Name: "old", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "1.0.0", AgentFeatures: []string{"self_update_v1"}},
		{ID: "srv_current", Name: "current", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "2.0.0", AgentFeatures: []string{"self_update_v1"}},
		{ID: "srv_legacy", Name: "legacy", Online: true, LastSeen: time.Now().UTC(), AgentVersion: "1.0.0"},
	} {
		if err := store.PutServer(server); err != nil {
			t.Fatal(err)
		}
	}
	body := `{"server_ids":["local","srv_old","srv_current","srv_legacy"],"action":"agent.update","args":{"version":"2.0.0"}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/batch/preflight", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.batchPreflight(recorder, request, types.Session{Username: initial.Username})
	if recorder.Code != http.StatusOK {
		t.Fatalf("preflight status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Eligible []struct {
			ID string `json:"id"`
		} `json:"eligible"`
		Skipped []struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Eligible) != 1 || result.Eligible[0].ID != "srv_old" || len(result.Skipped) != 3 {
		t.Fatalf("unexpected preflight result: %#v", result)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/batch/actions", strings.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.batchAction(recorder, request, types.Session{Username: initial.Username})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("batch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var batch struct {
		Tasks []types.Task `json:"tasks"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Tasks) != 1 || batch.Tasks[0].ServerID != "srv_old" || batch.Tasks[0].ExpectedStateDigest != "" {
		t.Fatalf("unexpected batch tasks: %#v", batch.Tasks)
	}
}

func mustURL(raw string) *url.URL { value, _ := url.Parse(raw); return value }
