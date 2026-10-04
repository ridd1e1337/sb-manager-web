package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/runner"
)

type request struct {
	Action string         `json:"action"`
	Args   map[string]any `json:"args"`
}

type response struct {
	Result runner.Result `json:"result"`
	Error  string        `json:"error,omitempty"`
}

type Server struct {
	Socket  string
	Runner  runner.Runner
	WebPath string
}

func (s Server) Serve(ctx context.Context) error {
	if s.Socket == "" {
		return errors.New("helper socket is empty")
	}
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0750); err != nil {
		return err
	}
	if err := os.Remove(s.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(s.Socket)
	if err := os.Chmod(s.Socket, 0660); err != nil {
		return err
	}
	// The helper service is started with Group=sbweb (or the configured
	// service group), so its effective GID is the least-privilege WebUI group.
	_ = os.Chown(s.Socket, os.Getuid(), os.Getgid())
	httpServer := &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/run" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var input request
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		write(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}
	if input.Action == "web.update" {
		if len(input.Args) != 0 {
			write(w, http.StatusBadRequest, response{Error: "web.update does not accept arguments"})
			return
		}
		result, runErr := s.update(r.Context())
		output := response{Result: result}
		if runErr != nil {
			output.Error = runErr.Error()
		} else {
			s.restartAfterUpdate()
		}
		write(w, http.StatusOK, output)
		return
	}
	command, err := runner.ActionCommand(input.Action, input.Args)
	if err != nil {
		write(w, http.StatusBadRequest, response{Error: err.Error()})
		return
	}
	result, runErr := s.Runner.Run(r.Context(), command...)
	output := response{Result: result}
	if runErr != nil {
		output.Error = runErr.Error()
	}
	write(w, http.StatusOK, output)
}

func (s Server) update(ctx context.Context) (runner.Result, error) {
	if s.WebPath == "" {
		return runner.Result{}, errors.New("WebUI 二进制路径为空")
	}
	timeout := s.Runner.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(updateCtx, s.WebPath, "update")
	command.Env = append(os.Environ(), "SBM_WEB_SKIP_HELPER_RESTART=1")
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	result := runner.Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if updateCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, fmt.Errorf("WebUI 更新超时（超过 %s）", timeout)
	}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("WebUI 更新退出码 %d", result.ExitCode)
	}
	return result, err
}

func (s Server) restartAfterUpdate() {
	go func() {
		time.Sleep(500 * time.Millisecond)
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			_ = exec.Command("systemctl", "restart", "sb-manager-web-helper.service").Run()
			return
		}
		if _, err := os.Stat("/etc/init.d/sb-manager-web-helper"); err == nil {
			_ = exec.Command("rc-service", "sb-manager-web-helper", "restart").Run()
		}
	}()
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type Client struct {
	Socket  string
	Timeout time.Duration
}

func (c Client) Run(ctx context.Context, action string, args map[string]any) (runner.Result, error) {
	if c.Socket == "" {
		return runner.Result{}, errors.New("helper socket is empty")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: c.Timeout}
	body, err := json.Marshal(request{Action: action, Args: args})
	if err != nil {
		return runner.Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/run", bytes.NewReader(body))
	if err != nil {
		return runner.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return runner.Result{}, err
	}
	defer resp.Body.Close()
	var output response
	if err := json.NewDecoder(http.MaxBytesReader(nilWriter{}, resp.Body, 128*1024)).Decode(&output); err != nil {
		return runner.Result{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return output.Result, fmt.Errorf("helper returned HTTP %d: %s", resp.StatusCode, output.Error)
	}
	if output.Error != "" {
		return output.Result, errors.New(output.Error)
	}
	return output.Result, nil
}

type nilWriter struct{}

func (nilWriter) Header() http.Header       { return make(http.Header) }
func (nilWriter) Write([]byte) (int, error) { return 0, nil }
func (nilWriter) WriteHeader(int)           {}
