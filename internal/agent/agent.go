package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/runner"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

type identity struct {
	PrivateKey        string `json:"private_key"`
	ServerID          string `json:"server_id"`
	ClientCertificate string `json:"client_certificate,omitempty"`
	ClientKey         string `json:"client_key,omitempty"`
	ClientCA          string `json:"client_ca,omitempty"`
}

type Agent struct {
	cfg        config.Config
	key        ed25519.PrivateKey
	server     string
	client     *http.Client
	runner     runner.Runner
	selfUpdate func(context.Context, string) (runner.Result, error)
	tlsCert    tls.Certificate
	tlsCA      *x509.CertPool
	tlsCAPEM   string
}

var Version = "dev"
var errAgentRestart = errors.New("agent update installed; restart required")

func New(cfg config.Config) (*Agent, error) {
	identityPath := cfg.Agent.IdentityFile
	if identityPath == "" {
		identityPath = filepath.Join(cfg.DataDir, "agent-identity", "ed25519.json")
	}
	data, err := os.ReadFile(identityPath)
	var saved identity
	if err == nil {
		if json.Unmarshal(data, &saved) != nil {
			return nil, errors.New("agent identity file is invalid")
		}
	}
	var key ed25519.PrivateKey
	if saved.PrivateKey != "" {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(saved.PrivateKey)
		if decodeErr != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("agent private key is invalid")
		}
		key = ed25519.PrivateKey(raw)
	} else {
		var generateErr error
		_, key, generateErr = ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			return nil, generateErr
		}
	}
	cfg.Agent.IdentityFile = identityPath
	a := &Agent{cfg: cfg, key: key, server: saved.ServerID, client: &http.Client{Timeout: 35 * time.Second}, runner: runner.Runner{Path: cfg.SBPath, Timeout: cfg.Tasks.DefaultTimeout}}
	a.selfUpdate = a.runSelfUpdate
	if saved.ClientCertificate != "" || saved.ClientKey != "" || saved.ClientCA != "" {
		if err := a.configureTLS(saved.ClientCertificate, saved.ClientKey, saved.ClientCA); err != nil {
			return nil, err
		}
	}
	if err := a.saveIdentity(identityPath); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Agent) saveIdentity(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	value := identity{PrivateKey: base64.RawURLEncoding.EncodeToString(a.key), ServerID: a.server}
	if len(a.tlsCert.Certificate) > 0 && a.tlsCA != nil {
		value.ClientCertificate, value.ClientKey, value.ClientCA = a.clientCertificatePEM()
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}

func (a *Agent) configureTLS(certPEM, keyPEM, caPEM string) error {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("parse Agent client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("parse Agent client CA failed")
	}
	a.tlsCert, a.tlsCA, a.tlsCAPEM = cert, pool, strings.TrimSpace(caPEM)+"\n"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Keep the platform/system roots for the controller certificate. The Agent
	// CA is only used to validate and persist the client identity; it must not
	// replace the roots used to authenticate the HTTPS controller.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{a.tlsCert}}
	a.client = &http.Client{Transport: transport, Timeout: 35 * time.Second}
	return nil
}

func (a *Agent) clientCertificatePEM() (string, string, string) {
	if len(a.tlsCert.Certificate) == 0 || a.tlsCA == nil {
		return "", "", ""
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.tlsCert.Certificate[0]})
	key, _ := x509.MarshalPKCS8PrivateKey(a.tlsCert.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	return string(cert), string(keyPEM), a.tlsCAPEM
}

func (a *Agent) Run(ctx context.Context) error {
	if strings.TrimSpace(a.cfg.Agent.ControllerURL) == "" {
		return errors.New("agent controller_url is empty")
	}
	if err := validateControllerURL(a.cfg.Agent.ControllerURL); err != nil {
		return err
	}
	if a.server == "" {
		if err := a.Register(ctx); err != nil {
			return err
		}
	}
	if err := a.heartbeat(ctx); err != nil {
		// A transient controller failure must not stop the Agent forever.
		fmt.Fprintf(os.Stderr, "sb-web agent heartbeat: %v\n", err)
	}
	interval := 30 * time.Second
	if value, err := time.ParseDuration(a.cfg.Agent.HeartbeatInterval); err == nil && value >= 5*time.Second {
		interval = value
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := a.heartbeat(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "sb-web agent heartbeat: %v\n", err)
				continue
			}
			if err := a.poll(ctx); errors.Is(err, errAgentRestart) {
				return nil
			} else if err != nil {
				fmt.Fprintf(os.Stderr, "sb-web agent poll: %v\n", err)
			}
			if err := a.maybeRotateCertificate(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "sb-web agent certificate rotation: %v\n", err)
			}
		}
	}
}

func validateControllerURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("controller URL is invalid")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return nil
	}
	return errors.New("remote controller must use HTTPS")
}

func (a *Agent) maybeRotateCertificate(ctx context.Context) error {
	if len(a.tlsCert.Certificate) == 0 {
		return nil
	}
	leaf := a.tlsCert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(a.tlsCert.Certificate[0])
		if err != nil {
			return err
		}
		leaf = parsed
		a.tlsCert.Leaf = leaf
	}
	if time.Until(leaf.NotAfter) > 7*24*time.Hour {
		return nil
	}
	data, err := a.post(ctx, "/api/v1/agent/rotate", map[string]any{}, true)
	if err != nil {
		return err
	}
	var response struct {
		ClientCertificate string `json:"client_certificate"`
		ClientKey         string `json:"client_key"`
		ClientCA          string `json:"client_ca"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	if response.ClientCertificate == "" || response.ClientKey == "" || response.ClientCA == "" {
		return errors.New("controller returned an incomplete client certificate")
	}
	if err := a.configureTLS(response.ClientCertificate, response.ClientKey, response.ClientCA); err != nil {
		return err
	}
	return a.saveIdentity(a.cfg.Agent.IdentityFile)
}

// Sync sends one heartbeat and handles at most one queued task.
func (a *Agent) Sync(ctx context.Context) error {
	if err := a.Register(ctx); err != nil {
		return err
	}
	if err := a.heartbeat(ctx); err != nil {
		return err
	}
	err := a.poll(ctx)
	if errors.Is(err, errAgentRestart) {
		return nil
	}
	return err
}

// Register performs one-time enrollment. The join command calls it before
// handing the long-running process to systemd/OpenRC.
func (a *Agent) Register(ctx context.Context) error {
	if err := validateControllerURL(a.cfg.Agent.ControllerURL); err != nil {
		return err
	}
	if a.server != "" {
		return nil
	}
	if a.cfg.Agent.EnrollmentToken == "" {
		return errors.New("agent enrollment_token is empty")
	}
	return a.register(ctx)
}

func (a *Agent) register(ctx context.Context) error {
	public := a.key.Public().(ed25519.PublicKey)
	body := map[string]any{"token": a.cfg.Agent.EnrollmentToken, "public_key": base64.RawURLEncoding.EncodeToString(public), "name": hostname(), "arch": runtime.GOARCH}
	data, err := a.post(ctx, "/api/v1/agent/register", body, false)
	if err != nil {
		return err
	}
	var response struct {
		ServerID          string `json:"server_id"`
		ClientCertificate string `json:"client_certificate"`
		ClientKey         string `json:"client_key"`
		ClientCA          string `json:"client_ca"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.ServerID == "" {
		return errors.New("controller returned invalid registration response")
	}
	a.server = response.ServerID
	if response.ClientCertificate != "" || response.ClientKey != "" || response.ClientCA != "" {
		if err := a.configureTLS(response.ClientCertificate, response.ClientKey, response.ClientCA); err != nil {
			return err
		}
	}
	if err := a.saveIdentity(a.cfg.Agent.IdentityFile); err != nil {
		return err
	}
	fmt.Printf("sb-web agent registered as %s\n", a.server)
	return nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "remote-server"
	}
	return name
}

func (a *Agent) heartbeat(ctx context.Context) error {
	status, _ := a.localJSON(ctx, "status")
	caps, _ := a.localJSON(ctx, "core.capabilities")
	nodes, _ := a.localJSON(ctx, "nodes.list")
	managerResult, _ := a.runner.Run(ctx, "version")
	body := map[string]any{
		"agent_version":      Version,
		"agent_features":     []string{"self_update_v1"},
		"sb_manager_version": strings.TrimSpace(managerResult.Stdout),
		"core_version":       capsValue(caps, "version"),
		"backend":            "",
		"status":             status,
		"capabilities":       caps,
		"node_snapshot":      nodes,
	}
	if digest, schema, digestErr := stateSnapshot(a.cfg.StateFile); digestErr == nil {
		body["state_digest"], body["state_schema"] = digest, schema
	}
	_, err := a.post(ctx, "/api/v1/agent/heartbeat", body, true)
	return err
}

func capsValue(data json.RawMessage, key string) string {
	var object map[string]any
	if json.Unmarshal(data, &object) != nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

func (a *Agent) localJSON(ctx context.Context, action string) (json.RawMessage, error) {
	command, err := runner.ActionCommand(action, nil)
	if err != nil {
		return nil, err
	}
	result, err := a.runner.Run(ctx, command...)
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(result.Stdout)) {
		return nil, errors.New("sb returned invalid JSON")
	}
	return json.RawMessage(result.Stdout), nil
}

func (a *Agent) poll(ctx context.Context) error {
	data, err := a.post(ctx, "/api/v1/agent/poll", map[string]any{}, true)
	if err != nil {
		return err
	}
	var response struct {
		Task *types.Task `json:"task"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	if response.Task == nil {
		return nil
	}
	if response.Task.Action != "agent.update" && response.Task.ExpectedStateDigest != "" {
		current, _, digestErr := stateSnapshot(a.cfg.StateFile)
		if digestErr != nil || current != response.Task.ExpectedStateDigest {
			_, err = a.post(ctx, "/api/v1/agent/result", map[string]any{"task_id": response.Task.ID, "status": types.TaskFailed, "output": "", "error": "state drift detected; refresh the server before retrying"}, true)
			return err
		}
	}
	result := runner.Result{}
	var commandErr error
	restart := false
	if response.Task.Action == "agent.update" {
		version, _ := response.Task.Args["version"].(string)
		if !runner.ValidVersion(version) {
			commandErr = errors.New("invalid Agent update version")
		} else if version == Version {
			result.Stdout = "Agent is already running version " + version
		} else {
			result, commandErr = a.selfUpdate(ctx, version)
			restart = commandErr == nil
		}
	} else {
		command, err := runner.ActionCommand(response.Task.Action, response.Task.Args)
		commandErr = err
		if commandErr == nil {
			result, commandErr = a.runner.Run(ctx, command...)
		}
	}
	status := types.TaskSuccess
	problem := ""
	if commandErr != nil {
		status, problem = types.TaskFailed, commandErr.Error()+"\n"+result.Stderr
	}
	_, err = a.post(ctx, "/api/v1/agent/result", map[string]any{"task_id": response.Task.ID, "status": status, "output": result.Stdout, "error": problem}, true)
	if restart {
		if err != nil {
			fmt.Fprintf(os.Stderr, "sb-web agent update result: %v\n", err)
		}
		return errAgentRestart
	}
	return err
}

func (a *Agent) runSelfUpdate(ctx context.Context, version string) (runner.Result, error) {
	if !runner.ValidVersion(version) {
		return runner.Result{}, errors.New("invalid Agent update version")
	}
	executable, err := os.Executable()
	if err != nil {
		return runner.Result{}, fmt.Errorf("locate Agent executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	args := selfUpdateArgs(a.cfg.ConfigPath, version)
	return (runner.Runner{Path: executable, Timeout: a.cfg.Tasks.DefaultTimeout}).Run(ctx, args...)
}

func selfUpdateArgs(configPath, version string) []string {
	args := []string{"update"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	return append(args, "--version", version, "--no-restart")
}

func stateSnapshot(path string) (string, int, error) {
	if path == "" {
		return "", 0, errors.New("state file is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	digest := sha256.Sum256(data)
	var metadata struct {
		Schema int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest[:]), metadata.Schema, nil
}

func (a *Agent) post(ctx context.Context, endpoint string, value any, signed bool) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(a.cfg.Agent.ControllerURL, "/") + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if signed {
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		message := req.Method + "\n" + endpoint + "\n" + timestamp + "\n" + string(body)
		signature := ed25519.Sign(a.key, []byte(message))
		req.Header.Set("X-Agent-ID", a.server)
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", base64.RawURLEncoding.EncodeToString(signature))
	}
	response, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := ioReadAllLimit(response, 128*1024)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("controller returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func ioReadAllLimit(response *http.Response, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("controller response is too large")
	}
	return data, nil
}
