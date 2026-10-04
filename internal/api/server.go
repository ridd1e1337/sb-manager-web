package api

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/auth"
	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/helper"
	"github.com/ridd1e1337/sb-manager-web/internal/runner"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
	"github.com/ridd1e1337/sb-manager-web/web"
)

const (
	sessionCookie = "sbweb_session"
	csrfCookie    = "sbweb_csrf"
	maxBodyBytes  = 128 * 1024
)

type Server struct {
	cfg              config.Config
	store            *storage.Store
	auth             *auth.Manager
	runner           runner.Runner
	mu               sync.Mutex
	sem              chan struct{}
	loginMu          sync.Mutex
	logins           map[string]loginAttempt
	agentCA          *agentCA
	webUpdateMu      sync.Mutex
	webUpdateRunning bool
}

type loginAttempt struct {
	Count        int
	BlockedUntil time.Time
}

func New(cfg config.Config, store *storage.Store) (*Server, auth.InitialCredential, error) {
	authManager := auth.New(store)
	credential, created, err := authManager.EnsureOwner()
	if err != nil {
		return nil, auth.InitialCredential{}, err
	}
	if err := store.PutServer(types.Server{ID: types.ServerLocal, Name: "本机", Online: true, LastSeen: time.Now().UTC()}); err != nil {
		return nil, auth.InitialCredential{}, err
	}
	if !created {
		credential = auth.InitialCredential{}
	}
	server := &Server{cfg: cfg, store: store, auth: authManager, runner: runner.Runner{Path: cfg.SBPath, Timeout: cfg.Tasks.DefaultTimeout}, sem: make(chan struct{}, cfg.Tasks.Concurrency), logins: make(map[string]loginAttempt)}
	if cfg.TLS.RequireAgentMTLS || cfg.TLS.ClientCAFile != "" || cfg.TLS.ClientCAKeyFile != "" {
		if err := server.ensureAgentCA(); err != nil {
			return nil, auth.InitialCredential{}, err
		}
	}
	return server, credential, nil
}

// ResumeLocalTasks schedules local work that was pending or requeued when the
// controller started. ClaimTask performs the final atomic duplicate check.
func (s *Server) ResumeLocalTasks() error {
	ids, err := s.store.ListPendingTaskIDs(types.ServerLocal)
	if err != nil {
		return err
	}
	for _, id := range ids {
		go s.executeLocal(id)
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/servers/", s.detailPage)
	mux.HandleFunc("/settings/users", s.usersPage)
	mux.HandleFunc("/operations", s.operationsPage)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/static/", s.static)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "database unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/v1/", s.api)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.session(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl, err := template.ParseFS(web.Files, "templates/index.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	version := s.cfg.WebVersion
	if version == "" {
		version = "dev"
	}
	_ = tmpl.Execute(w, map[string]any{"Version": version})
}

func (s *Server) detailPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "servers" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"ServerID": parts[1], "NodeID": ""}
	name := "templates/server.html"
	if len(parts) == 4 && parts[2] == "nodes" && parts[3] != "" {
		name = "templates/node.html"
		data["NodeID"] = parts[3]
	} else if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	tmpl, err := template.ParseFS(web.Files, name)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, data)
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl, err := template.ParseFS(web.Files, "templates/users.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, nil)
}

func (s *Server) operationsPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl, err := template.ParseFS(web.Files, "templates/operations.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, nil)
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/static/")
	if name == "" || name == "." || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := web.Files.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	}
	_, _ = w.Write(data)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFS(web.Files, "templates/login.html")
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	otp := r.FormValue("otp")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !s.loginAllowed(ip) {
		http.Error(w, "登录尝试过多，请稍后再试", http.StatusTooManyRequests)
		return
	}
	if username == "" || len(password) > 256 || !s.auth.Authenticate(username, password) {
		s.recordLoginFailure(ip)
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	user, userErr := s.store.GetUser(username)
	if userErr != nil {
		s.recordLoginFailure(ip)
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	if user.TOTPEnabled && !auth.VerifyTOTP(user.TOTPSecret, otp, time.Now().UTC()) {
		if !auth.ConsumeRecoveryCode(&user, otp) {
			s.recordLoginFailure(ip)
			http.Error(w, "双因素验证码错误", http.StatusUnauthorized)
			return
		}
		_ = s.store.PutUser(user)
	}
	s.clearLoginFailures(ip)
	session, err := s.auth.NewSession(username)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 43200})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: session.CSRF, Path: "/", HttpOnly: false, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 43200})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginAllowed(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	attempt := s.logins[ip]
	return !attempt.BlockedUntil.After(time.Now())
}

func (s *Server) recordLoginFailure(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	attempt := s.logins[ip]
	attempt.Count++
	if attempt.Count >= 5 {
		minutes := attempt.Count - 4
		if minutes > 15 {
			minutes = 15
		}
		attempt.BlockedUntil = time.Now().Add(time.Duration(minutes) * time.Minute)
	}
	s.logins[ip] = attempt
}

func (s *Server) clearLoginFailures(ip string) {
	s.loginMu.Lock()
	delete(s.logins, ip)
	s.loginMu.Unlock()
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if session, ok := s.session(r); ok && s.checkCSRF(r, session) {
		_ = s.auth.DeleteSession(session.ID)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) session(r *http.Request) (types.Session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return types.Session{}, false
	}
	return s.auth.ValidateSession(cookie.Value)
}

func (s *Server) checkCSRF(r *http.Request, session types.Session) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	value := r.Header.Get("X-CSRF-Token")
	if value == "" {
		if cookie, err := r.Cookie(csrfCookie); err == nil {
			value = cookie.Value
		}
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(session.CSRF)) == 1
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (types.Session, bool) {
	session, ok := s.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "需要登录", nil)
		return types.Session{}, false
	}
	if !s.checkCSRF(r, session) {
		writeError(w, http.StatusForbidden, "CSRF_FAILED", "CSRF 校验失败", nil)
		return types.Session{}, false
	}
	return session, true
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/agent/register" {
		s.agentRegister(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/agent/") {
		s.agentAPI(w, r)
		return
	}
	if r.URL.Path == "/api/v1/metrics" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		if _, ok := s.auth.AuthenticateAPIToken(strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))); ok {
			s.metrics(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "API_TOKEN_INVALID", "API Token 无效或权限不足", nil)
		return
	}
	session, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet && r.URL.Path != "/api/v1/password" && !strings.HasPrefix(r.URL.Path, "/api/v1/2fa/") && s.auth.Role(session.Username) == "viewer" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "当前账号只有只读权限", nil)
		return
	}
	if r.URL.Path == "/api/v1/enrollment" && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以添加服务器", nil)
		return
	}
	if r.URL.Path == "/api/v1/web/update" && r.Method == http.MethodPost && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以更新 WebUI", nil)
		return
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/servers/") && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以撤销服务器", nil)
		return
	}
	switch r.URL.Path {
	case "/api/v1/session":
		user, _ := s.store.GetUser(session.Username)
		writeJSON(w, http.StatusOK, map[string]any{"username": session.Username, "role": s.auth.Role(session.Username), "totp_enabled": user.TOTPEnabled, "csrf": session.CSRF})
	case "/api/v1/web/update":
		s.webUpdate(w, r, session)
	case "/api/v1/password":
		s.changePassword(w, r, session)
	case "/api/v1/2fa/setup":
		s.twoFASetup(w, r, session)
	case "/api/v1/2fa/enable":
		s.twoFAEnable(w, r, session)
	case "/api/v1/2fa/disable":
		s.twoFADisable(w, r, session)
	case "/api/v1/status":
		s.singleJSONAction(w, r, "status")
	case "/api/v1/nodes":
		s.singleJSONAction(w, r, "nodes.list")
	case "/api/v1/capabilities":
		s.singleJSONAction(w, r, "core.capabilities")
	case "/api/v1/bbr/status":
		s.singleJSONAction(w, r, "bbr.status")
	case "/api/v1/hy2-buffer/status":
		s.singleJSONAction(w, r, "hy2-buffer.status")
	case "/api/v1/realm":
		s.singleJSONAction(w, r, "realm.status")
	case "/api/v1/traffic":
		s.singleJSONAction(w, r, "traffic.status")
	case "/api/v1/health":
		s.singleJSONAction(w, r, "health.status")
	case "/api/v1/firewall":
		s.singleJSONAction(w, r, "firewall.status")
	case "/api/v1/firewall/ports":
		s.singleJSONAction(w, r, "firewall.ports")
	case "/api/v1/mux":
		s.singleJSONAction(w, r, "mux.status")
	case "/api/v1/mux/routes":
		s.singleJSONAction(w, r, "mux.route.list")
	case "/api/v1/tunnel":
		s.singleJSONAction(w, r, "tunnel.status")
	case "/api/v1/tunnel/configure":
		s.tunnelConfigure(w, r, session)
	case "/api/v1/tunnel/token":
		s.tunnelToken(w, r, session)
	case "/api/v1/notify":
		s.singleJSONAction(w, r, "notify.status")
	case "/api/v1/api":
		s.singleJSONAction(w, r, "api.status")
	case "/api/v1/probe":
		s.probe(w, r)
	case "/api/v1/notify/configure":
		s.notifyConfigure(w, r, session)
	case "/api/v1/settings":
		s.singleJSONAction(w, r, "settings.show")
	case "/api/v1/config/validate":
		s.singleJSONAction(w, r, "config.validate")
	case "/api/v1/config/diff":
		s.singleJSONAction(w, r, "config.diff")
	case "/api/v1/metrics":
		s.metrics(w, r)
	case "/api/v1/metrics/history":
		s.metricsHistory(w, r)
	case "/api/v1/events":
		s.events(w, r)
	case "/api/v1/certificates":
		s.singleJSONAction(w, r, "cert.list")
	case "/api/v1/certificates/cloudflare":
		s.cloudflareConfigure(w, r, session)
	case "/api/v1/logs":
		s.logs(w, r)
	case "/api/v1/shares":
		s.shares(w, r)
	case "/api/v1/exports/outbounds":
		s.exportsOutbounds(w, r)
	case "/api/v1/subscriptions":
		s.subscriptions(w, r)
	case "/api/v1/subscriptions/status":
		s.subscriptionStatus(w, r)
	case "/api/v1/servers":
		s.servers(w, r)
	case "/api/v1/enrollment":
		s.enrollment(w, r)
	case "/api/v1/tasks":
		s.tasks(w, r)
	case "/api/v1/audit":
		s.audit(w, r)
	case "/api/v1/users":
		s.usersAPI(w, r, session)
	case "/api/v1/tokens":
		s.tokensAPI(w, r, session)
	case "/api/v1/database/backup":
		s.databaseBackup(w, r, session)
	case "/api/v1/backups":
		s.backupsAPI(w, r, session)
	case "/api/v1/batch/actions":
		s.batchAction(w, r, session)
	case "/api/v1/batch/preflight":
		s.batchPreflight(w, r, session)
	default:
		if strings.HasPrefix(r.URL.Path, "/api/v1/backups/") {
			s.backupsAPI(w, r, session)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/tokens/") {
			s.tokensAPI(w, r, session)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/certificates/") {
			s.certificateInspect(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/users/") {
			s.usersAPI(w, r, session)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/servers/") {
			s.serverAPI(w, r, session)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/tasks/") {
			s.taskAPI(w, r, session)
			return
		}
		writeError(w, http.StatusNotFound, "NOT_FOUND", "接口不存在", nil)
	}
}

func (s *Server) certificateInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	domain := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "域名不能为空", nil)
		return
	}
	result, err := s.runLocal("cert.inspect", map[string]any{"domain": domain})
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	if !json.Valid([]byte(result.Stdout)) {
		writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, result.Stdout)
}

func (s *Server) databaseBackup(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	if s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以备份控制端数据库", nil)
		return
	}
	now := time.Now().UTC()
	destination := filepath.Join(s.cfg.DataDir, "backups", "web-"+now.Format("20060102T150405Z")+"-"+strconv.FormatInt(now.UnixNano()%1000000, 10)+".db")
	if err := s.store.Backup(r.Context(), destination); err != nil {
		writeError(w, http.StatusInternalServerError, "BACKUP_FAILED", err.Error(), nil)
		return
	}
	s.recordAudit(session.Username, "database.backup", nil, nil, "success")
	writeJSON(w, http.StatusCreated, map[string]any{"path": destination})
}

func (s *Server) backupsAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	if s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以管理备份", nil)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 3 && r.Method == http.MethodGet {
		entries, err := os.ReadDir(s.cfg.BackupDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		values := []map[string]any{}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".tar.gz") && !strings.HasSuffix(entry.Name(), ".age")) {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			values = append(values, map[string]any{"name": entry.Name(), "size": info.Size(), "modified_at": info.ModTime().UTC()})
		}
		writeJSON(w, http.StatusOK, map[string]any{"backups": values})
		return
	}
	if len(parts) == 3 && r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "备份上传失败", nil)
			return
		}
		file, header, err := r.FormFile("backup")
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "缺少 backup 文件", nil)
			return
		}
		defer file.Close()
		name := filepath.Base(header.Filename)
		if name == "." || name == ".." || (!strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".age")) || strings.ContainsAny(name, "\r\n\x00") {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "备份文件名或格式无效", nil)
			return
		}
		if err := os.MkdirAll(s.cfg.BackupDir, 0700); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		tmp, err := os.CreateTemp(s.cfg.BackupDir, ".upload-*")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		written, copyErr := io.Copy(tmp, io.LimitReader(file, (128<<20)+1))
		if copyErr != nil {
			tmp.Close()
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", copyErr.Error(), nil)
			return
		}
		if written > 128<<20 {
			tmp.Close()
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "备份文件超过 128 MiB", nil)
			return
		}
		if err := tmp.Close(); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		destination := filepath.Join(s.cfg.BackupDir, name)
		if _, err := os.Stat(destination); err == nil {
			writeError(w, http.StatusConflict, "BACKUP_EXISTS", "同名备份已存在", nil)
			return
		}
		if err := os.Rename(tmpName, destination); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "backup.upload", nil, nil, "success")
		writeJSON(w, http.StatusCreated, map[string]any{"name": name})
		return
	}
	if len(parts) == 5 && r.Method == http.MethodPost && parts[4] == "restore" {
		name := parts[3]
		if filepath.Base(name) != name || (!strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".age")) {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "备份名称无效", nil)
			return
		}
		archive := filepath.Join(s.cfg.BackupDir, name)
		if _, err := os.Stat(archive); err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "备份不存在", nil)
			return
		}
		result, runErr := s.runLocal("restore", map[string]any{"archive": archive})
		if runErr != nil {
			writeRunnerError(w, runErr, result)
			return
		}
		s.recordAudit(session.Username, "backup.restore", nil, nil, "success")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": redact(result.Stdout)})
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST", nil)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decodeBody(r, &request); err != nil || !s.auth.Authenticate(session.Username, request.Current) {
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", "当前密码错误", nil)
		return
	}
	if err := s.auth.SetPassword(session.Username, request.New); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	_ = s.auth.DeleteSession(session.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "login_required": true})
}

func (s *Server) twoFASetup(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	secret, uri, err := s.auth.SetupTOTP(session.Username)
	if err != nil {
		writeError(w, http.StatusConflict, "2FA_SETUP_FAILED", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth_uri": uri, "message": "请在验证器中添加后调用 enable 接口确认"})
}

func (s *Server) twoFAEnable(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &request); err != nil || request.Code == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "code 必填", nil)
		return
	}
	codes, err := s.auth.EnableTOTP(session.Username, request.Code)
	if err != nil {
		writeError(w, http.StatusBadRequest, "2FA_ENABLE_FAILED", err.Error(), nil)
		return
	}
	s.recordAudit(session.Username, "2fa.enable", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes": codes})
}

func (s *Server) twoFADisable(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &request); err != nil || request.Code == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "code 必填", nil)
		return
	}
	if err := s.auth.DisableTOTP(session.Username, request.Code); err != nil {
		writeError(w, http.StatusBadRequest, "2FA_DISABLE_FAILED", err.Error(), nil)
		return
	}
	s.recordAudit(session.Username, "2fa.disable", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

func (s *Server) plainAction(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal(action, nil)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": truncate(redact(result.Stdout), 65536)})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	args := map[string]any{}
	if target := r.URL.Query().Get("target"); target != "" {
		args["target"] = target
	}
	if lines := r.URL.Query().Get("lines"); lines != "" {
		value, err := strconv.Atoi(lines)
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "lines 无效", nil)
			return
		}
		args["lines"] = float64(value)
	}
	result, err := s.runLocal("logs", args)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": args["target"], "output": truncate(redact(result.Stdout), 65536)})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal("status", nil)
	if err != nil && !json.Valid([]byte(result.Stdout)) {
		writeRunnerError(w, err, result)
		return
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &status); err != nil {
		writeError(w, http.StatusBadGateway, "INVALID_SB_JSON", "sb 返回了无效 JSON", nil)
		return
	}
	_ = s.store.PutMetric(time.Now().UTC(), status)
	metricLines := []string{"# HELP sb_manager_up Whether sb-manager status is available.", "# TYPE sb_manager_up gauge", "sb_manager_up 1"}
	if summary, ok := status["summary"].(map[string]any); ok {
		for key, metric := range map[string]string{"nodes": "sb_manager_nodes", "enabled_nodes": "sb_manager_enabled_nodes", "certificates": "sb_manager_certificates", "issues": "sb_manager_issues"} {
			if value, ok := summary[key].(float64); ok {
				metricLines = append(metricLines, fmt.Sprintf("%s %g", metric, value))
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(w, strings.Join(metricLines, "\n")+"\n")
}

func (s *Server) metricsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	hours := 24
	if value := r.URL.Query().Get("hours"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 168 {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "hours 必须是 1-168", nil)
			return
		}
		hours = parsed
	}
	values, err := s.store.ListMetrics(time.Now().UTC().Add(-time.Duration(hours)*time.Hour), 10000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "metrics": values})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED", "服务器不支持事件流", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	last := ""
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			tasks, err := s.store.ListTasks(20)
			if err != nil {
				return
			}
			payload, err := json.Marshal(map[string]any{"tasks": tasks})
			if err != nil {
				return
			}
			stamp := string(payload)
			if stamp == last {
				_, _ = io.WriteString(w, ": heartbeat\n\n")
				flusher.Flush()
				continue
			}
			last = stamp
			_, _ = io.WriteString(w, "event: tasks\ndata: "+stamp+"\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	result, err := s.runLocal("probe", map[string]any{"node_id": nodeID})
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "output": redact(result.Stdout)})
}

func (s *Server) shares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal("share.all", nil)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	// Share URIs are credentials. This endpoint is deliberately synchronous and
	// never creates a persisted task or audit payload; the browser must opt in
	// to display the one-time response.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
}

func (s *Server) exportsOutbounds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal("export.outbounds", nil)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
}

func (s *Server) notifyConfigure(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Provider   string `json:"provider"`
		Credential string `json:"credential"`
		ChatID     string `json:"chat_id"`
		Thresholds string `json:"thresholds"`
	}
	if err := decodeBody(r, &request); err != nil || request.Credential == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "provider 和 credential 必填", nil)
		return
	}
	if len(request.Credential) > 4096 || strings.ContainsAny(request.Credential, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "credential 无效", nil)
		return
	}
	tmp, err := os.CreateTemp(s.cfg.DataDir, ".notification-credential-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	if _, err := tmp.WriteString(request.Credential + "\n"); err != nil {
		tmp.Close()
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	if err := tmp.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	args := map[string]any{"provider": request.Provider, "credential_file": tmpName, "chat_id": request.ChatID, "thresholds": request.Thresholds}
	if _, err := runner.ActionCommand("notify.configure", args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	result, runErr := s.runLocal("notify.configure", args)
	if runErr != nil {
		writeRunnerError(w, runErr, result)
		return
	}
	s.recordAudit(session.Username, "notify.configure", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": redact(result.Stdout)})
}

func (s *Server) cloudflareConfigure(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Token  string `json:"token"`
		ZoneID string `json:"zone_id"`
		Email  string `json:"email"`
	}
	if err := decodeBody(r, &request); err != nil || request.Token == "" || request.Email == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "token 和 email 必填", nil)
		return
	}
	if len(request.Token) > 4096 || strings.ContainsAny(request.Token, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "token 无效", nil)
		return
	}
	args := map[string]any{"token": request.Token, "zone_id": request.ZoneID, "email": request.Email}
	if _, err := runner.ActionCommand("cert.setup-cloudflare", args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	result, runErr := s.runLocal("cert.setup-cloudflare", args)
	if runErr != nil {
		writeRunnerError(w, runErr, result)
		return
	}
	s.recordAudit(session.Username, "cert.setup-cloudflare", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": redact(result.Stdout)})
}

func (s *Server) tunnelConfigure(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		NodeID        string `json:"node_id"`
		Domain        string `json:"domain"`
		Token         string `json:"token"`
		ClientAddress string `json:"client_address"`
	}
	if err := decodeBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	args := map[string]any{"node_id": request.NodeID, "domain": request.Domain, "token": request.Token, "client_address": request.ClientAddress}
	if _, err := runner.ActionCommand("tunnel.fixed", args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	result, runErr := s.runLocal("tunnel.fixed", args)
	if runErr != nil {
		writeRunnerError(w, runErr, result)
		return
	}
	s.recordAudit(session.Username, "tunnel.fixed", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": redact(result.Stdout)})
}

func (s *Server) tunnelToken(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if err := decodeBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	args := map[string]any{"token": request.Token}
	if _, err := runner.ActionCommand("tunnel.set-token", args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	result, runErr := s.runLocal("tunnel.set-token", args)
	if runErr != nil {
		writeRunnerError(w, runErr, result)
		return
	}
	s.recordAudit(session.Username, "tunnel.set-token", nil, nil, "success")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": redact(result.Stdout)})
}

func (s *Server) subscriptionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal("subscription.status", nil)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
}

func (s *Server) subscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		result, err := s.runLocal("subscription.list", nil)
		if err != nil {
			writeRunnerError(w, err, result)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST、DELETE", nil)
		return
	}
	var request struct {
		Duration string `json:"duration"`
		Mode     string `json:"mode"`
		Token    string `json:"token"`
	}
	if r.Method == http.MethodPost {
		if err := decodeBody(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		result, err := s.runLocal("subscription.create", map[string]any{"duration": request.Duration, "mode": request.Mode})
		if err != nil {
			writeRunnerError(w, err, result)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"output": redact(result.Stdout)})
		return
	}
	if err := decodeBody(r, &request); err != nil || request.Token == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "token 必填", nil)
		return
	}
	result, err := s.runLocal("subscription.revoke", map[string]any{"token": request.Token})
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": redact(result.Stdout)})
}

func (s *Server) batchAction(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		ServerIDs []string       `json:"server_ids"`
		Action    string         `json:"action"`
		Args      map[string]any `json:"args"`
		Strategy  string         `json:"strategy"`
		Percent   int            `json:"percentage"`
	}
	if err := decodeBody(r, &request); err != nil || len(request.ServerIDs) == 0 || len(request.ServerIDs) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "server_ids 必须包含 1-100 台服务器", nil)
		return
	}
	if request.Args == nil {
		request.Args = map[string]any{}
	}
	if request.Action == "agent.update" && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以更新 Agent", nil)
		return
	}
	if sensitiveAction(request.Action) {
		writeError(w, http.StatusBadRequest, "SENSITIVE_ACTION_DIRECT_ONLY", "该操作不支持批量队列，请使用专用接口", nil)
		return
	}
	if request.Strategy == "" {
		request.Strategy = "all"
	}
	if request.Strategy != "all" && request.Strategy != "canary" && request.Strategy != "percentage" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "strategy 必须是 all、canary 或 percentage", nil)
		return
	}
	if request.Strategy == "percentage" && (request.Percent < 1 || request.Percent > 100) {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "percentage 必须是 1-100", nil)
		return
	}
	if request.Strategy != "percentage" {
		request.Percent = 100
	}
	if err := validateQueuedAction(request.Action, request.Args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	batchID, _ := auth.RandomToken(10)
	created := []types.Task{}
	eligible := []string{}
	for _, serverID := range request.ServerIDs {
		server, err := s.store.GetServer(serverID)
		if err != nil {
			continue
		}
		if request.Action == "agent.update" {
			version, _ := request.Args["version"].(string)
			if serverID == types.ServerLocal || !server.Online || !supportsAgentUpdate(server) || server.AgentVersion == version {
				continue
			}
		} else if serverID != types.ServerLocal && !server.Online {
			continue
		}
		eligible = append(eligible, serverID)
	}
	limit := len(eligible)
	if request.Strategy == "canary" {
		limit = 1
	} else if request.Strategy == "percentage" {
		limit = (len(eligible)*request.Percent + 99) / 100
		if limit < 1 && len(eligible) > 0 {
			limit = 1
		}
	}
	if limit > len(eligible) {
		limit = len(eligible)
	}
	for _, serverID := range eligible[:limit] {
		server, err := s.store.GetServer(serverID)
		if err != nil {
			continue
		}
		id, err := auth.RandomToken(12)
		if err != nil {
			continue
		}
		task := types.Task{ID: "task_" + id, ServerID: serverID, Action: request.Action, Args: request.Args, Status: types.TaskPending, CreatedAt: time.Now().UTC(), IdempotencyKey: "batch_" + batchID + "_" + serverID, BatchID: "batch_" + batchID, ExpectedStateDigest: expectedDigestForAction(server, request.Action)}
		if s.store.PutTask(task) != nil {
			continue
		}
		created = append(created, task)
		if serverID == types.ServerLocal {
			go s.executeLocal(task.ID)
		}
	}
	if len(created) == 0 {
		writeError(w, http.StatusConflict, "NO_ELIGIBLE_SERVERS", "没有符合条件的可执行服务器", nil)
		return
	}
	taskIDs := make([]string, 0, len(created))
	for _, task := range created {
		taskIDs = append(taskIDs, task.ID)
	}
	s.recordAudit(session.Username, request.Action, request.ServerIDs, taskIDs, "accepted")
	writeJSON(w, http.StatusAccepted, map[string]any{"batch_id": "batch_" + batchID, "strategy": request.Strategy, "percentage": request.Percent, "tasks": created})
}

func (s *Server) batchPreflight(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request struct {
		ServerIDs []string       `json:"server_ids"`
		Action    string         `json:"action"`
		Args      map[string]any `json:"args"`
	}
	if err := decodeBody(r, &request); err != nil || len(request.ServerIDs) == 0 || len(request.ServerIDs) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "server_ids 必须包含 1-100 台服务器", nil)
		return
	}
	if request.Args == nil {
		request.Args = map[string]any{}
	}
	if request.Action == "agent.update" && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以更新 Agent", nil)
		return
	}
	if err := validateQueuedAction(request.Action, request.Args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	type candidate struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Online       bool   `json:"online"`
		StateDigest  string `json:"state_digest,omitempty"`
		CoreVersion  string `json:"core_version,omitempty"`
		AgentVersion string `json:"agent_version,omitempty"`
		Reason       string `json:"reason,omitempty"`
	}
	result := struct {
		Action   string      `json:"action"`
		Eligible []candidate `json:"eligible"`
		Skipped  []candidate `json:"skipped"`
	}{Action: request.Action, Eligible: []candidate{}, Skipped: []candidate{}}
	for _, id := range request.ServerIDs {
		server, err := s.store.GetServer(id)
		if err != nil {
			result.Skipped = append(result.Skipped, candidate{ID: id, Reason: "server not found"})
			continue
		}
		item := candidate{ID: server.ID, Name: server.Name, Online: server.Online, StateDigest: server.StateDigest, CoreVersion: server.CoreVersion, AgentVersion: server.AgentVersion}
		if request.Action == "agent.update" && server.ID == types.ServerLocal {
			item.Reason = "local controller is updated separately"
			result.Skipped = append(result.Skipped, item)
		} else if server.ID != types.ServerLocal && !server.Online {
			item.Reason = "offline"
			result.Skipped = append(result.Skipped, item)
		} else if request.Action == "agent.update" && !supportsAgentUpdate(server) {
			item.Reason = "self-update unsupported; run sudo sb-web update once"
			result.Skipped = append(result.Skipped, item)
		} else if request.Action == "agent.update" && server.AgentVersion == firstNonEmptyString(request.Args["version"]) {
			item.Reason = "already current"
			result.Skipped = append(result.Skipped, item)
		} else {
			result.Eligible = append(result.Eligible, item)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	events, err := s.store.ListAudit(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) usersAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "users" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "用户接口不存在", nil)
		return
	}
	if len(parts) == 3 && r.Method == http.MethodGet {
		users, err := s.store.ListUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
		return
	}
	if s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以管理用户", nil)
		return
	}
	if len(parts) == 3 && r.Method == http.MethodPost {
		var request struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeBody(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		if err := s.auth.CreateUser(request.Username, request.Password, request.Role); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "user.create", nil, nil, "accepted")
		writeJSON(w, http.StatusCreated, map[string]any{"username": request.Username, "role": s.auth.Role(request.Username)})
		return
	}
	if len(parts) != 4 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "用户接口不存在", nil)
		return
	}
	username := parts[3]
	switch r.Method {
	case http.MethodPatch:
		var request struct {
			Role string `json:"role"`
		}
		if err := decodeBody(r, &request); err != nil || request.Role == "" {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "role 必填", nil)
			return
		}
		if request.Role != "admin" && s.auth.Role(username) == "admin" {
			users, listErr := s.store.ListUsers()
			admins := 0
			for _, user := range users {
				if s.auth.Role(user.Username) == "admin" {
					admins++
				}
			}
			if listErr != nil || admins <= 1 {
				writeError(w, http.StatusConflict, "LAST_ADMIN_REQUIRED", "至少需要保留一个管理员", nil)
				return
			}
		}
		if err := s.auth.SetRole(username, request.Role); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "user.role", nil, nil, "accepted")
		writeJSON(w, http.StatusOK, map[string]any{"username": username, "role": request.Role})
	case http.MethodDelete:
		if username == session.Username {
			writeError(w, http.StatusConflict, "USER_PROTECTED", "不能删除当前登录用户", nil)
			return
		}
		if _, err := s.store.GetUser(username); err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "用户不存在", nil)
			return
		}
		if s.auth.Role(username) == "admin" {
			users, listErr := s.store.ListUsers()
			admins := 0
			for _, user := range users {
				if s.auth.Role(user.Username) == "admin" {
					admins++
				}
			}
			if listErr != nil || admins <= 1 {
				writeError(w, http.StatusConflict, "LAST_ADMIN_REQUIRED", "至少需要保留一个管理员", nil)
				return
			}
		}
		if err := s.store.DeleteUser(username); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "user.delete", nil, nil, "accepted")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": username})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST、PATCH、DELETE", nil)
	}
}

func (s *Server) tokensAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	if s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以管理 API Token", nil)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 3 && r.Method == http.MethodGet {
		values, err := s.store.ListAPITokens()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": values})
		return
	}
	if len(parts) == 3 && r.Method == http.MethodPost {
		var request struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if err := decodeBody(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		value, raw, err := s.auth.CreateAPIToken(request.Name, request.Role)
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "api-token.create", nil, nil, "success")
		writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "metadata": value})
		return
	}
	if len(parts) == 4 && r.Method == http.MethodDelete {
		if err := s.store.DeleteAPIToken(parts[3]); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "api-token.delete", nil, nil, "success")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": parts[3]})
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST、DELETE", nil)
}

func (s *Server) recordAudit(actor, action string, serverIDs, taskIDs []string, result string) {
	id, err := auth.RandomToken(10)
	if err != nil {
		return
	}
	_ = s.store.PutAudit(types.AuditEvent{ID: "evt_" + id, Actor: actor, Action: action, ServerIDs: serverIDs, TaskIDs: taskIDs, Result: result, CreatedAt: time.Now().UTC()})
}

func (s *Server) singleJSONAction(w http.ResponseWriter, r *http.Request, action string) {
	s.jsonAction(w, r, action, nil)
}

func (s *Server) jsonAction(w http.ResponseWriter, r *http.Request, action string, args map[string]any) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	result, err := s.runLocal(action, args)
	if err != nil {
		writeRunnerError(w, err, result)
		return
	}
	if !json.Valid([]byte(result.Stdout)) {
		writeError(w, http.StatusBadGateway, "INVALID_SB_JSON", "sb 返回了无效 JSON", map[string]any{"stderr": result.Stderr})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, result.Stdout)
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	servers, err := s.store.ListServers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	now := time.Now().UTC()
	for index := range servers {
		if servers[index].ID != types.ServerLocal && now.Sub(servers[index].LastSeen) > 2*time.Minute {
			servers[index].Online = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
}

func (s *Server) enrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	token, err := auth.RandomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "RANDOM_FAILED", err.Error(), nil)
		return
	}
	expires := time.Now().UTC().Add(10 * time.Minute)
	if err := s.store.PutEnrollment(auth.HashEnrollmentToken(token), types.EnrollmentToken{Hash: auth.HashEnrollmentToken(token), ExpiresAt: expires}); err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	baseURL := "http://" + r.Host
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https") {
		baseURL = "https://" + r.Host
	}
	installURL := "https://github.com/ridd1e1337/sb-manager-web/raw/main/install.sh"
	writeJSON(w, http.StatusCreated, map[string]any{
		"expires_at":   expires,
		"token":        token,
		"join_command": fmt.Sprintf("curl -fsSL %s | sudo bash -s -- --agent %s %s", shellQuote(installURL), shellQuote(baseURL), shellQuote(token)),
	})
}

const webRepository = "ridd1e1337/sb-manager-web"

type webRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

func (s *Server) webUpdate(w http.ResponseWriter, r *http.Request, session types.Session) {
	switch r.Method {
	case http.MethodGet:
		release, err := latestWebRelease(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, "UPDATE_CHECK_FAILED", err.Error(), nil)
			return
		}
		current := s.cfg.WebVersion
		if current == "" {
			current = "dev"
		}
		latest := strings.TrimPrefix(release.TagName, "v")
		_, helperErr := os.Stat(s.cfg.HelperSocket)
		writeJSON(w, http.StatusOK, map[string]any{
			"current":          current,
			"latest":           latest,
			"update_available": latest != "" && latest != current,
			"release_url":      release.HTMLURL,
			"published_at":     release.PublishedAt,
			"can_update":       s.auth.Role(session.Username) == "admin",
			"update_supported": s.cfg.HelperSocket != "" && helperErr == nil,
		})
	case http.MethodPost:
		if s.cfg.HelperSocket == "" {
			writeError(w, http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE", "未配置 WebUI 特权更新服务，请使用 sudo sb-web update", nil)
			return
		}
		if _, err := os.Stat(s.cfg.HelperSocket); err != nil {
			writeError(w, http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE", "WebUI 特权更新服务未运行，请使用 sudo sb-web update 或启动 helper 服务", nil)
			return
		}
		s.webUpdateMu.Lock()
		if s.webUpdateRunning {
			s.webUpdateMu.Unlock()
			writeError(w, http.StatusConflict, "UPDATE_IN_PROGRESS", "WebUI 更新正在进行中", nil)
			return
		}
		s.webUpdateRunning = true
		s.webUpdateMu.Unlock()
		s.recordAudit(session.Username, "web.update", []string{types.ServerLocal}, nil, "accepted")
		go func() {
			_, err := s.runLocal("web.update", nil)
			s.webUpdateMu.Lock()
			s.webUpdateRunning = false
			s.webUpdateMu.Unlock()
			if err != nil {
				s.recordAudit(session.Username, "web.update", []string{types.ServerLocal}, nil, "failed")
			}
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "message": "WebUI 更新已开始，服务完成重启后请刷新页面。"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST", nil)
	}
}

func latestWebRelease(parent context.Context) (webRelease, error) {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+webRepository+"/releases/latest", nil)
	if err != nil {
		return webRelease{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "sb-manager-web")
	response, err := (&http.Client{Timeout: 9 * time.Second}).Do(request)
	if err != nil {
		return webRelease{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return webRelease{}, fmt.Errorf("GitHub 返回 HTTP %d", response.StatusCode)
	}
	var release webRelease
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&release); err != nil {
		return webRelease{}, fmt.Errorf("解析 GitHub Release 失败：%w", err)
	}
	if release.TagName == "" {
		return webRelease{}, errors.New("GitHub 没有可用的 Release")
	}
	return release, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

type actionRequest struct {
	Action         string         `json:"action"`
	Args           map[string]any `json:"args"`
	IdempotencyKey string         `json:"idempotency_key"`
}

func (s *Server) serverAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "servers" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器接口不存在", nil)
		return
	}
	serverID := parts[3]
	if len(parts) == 4 && r.Method == http.MethodGet {
		server, err := s.store.GetServer(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		server.AgentPublicKey = ""
		writeJSON(w, http.StatusOK, server)
		return
	}
	if len(parts) == 4 && r.Method == http.MethodDelete {
		if serverID == types.ServerLocal {
			writeError(w, http.StatusConflict, "LOCAL_SERVER_PROTECTED", "不能删除本机服务器", nil)
			return
		}
		if _, err := s.store.GetServer(serverID); err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		if err := s.store.DeleteServer(serverID); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "server.revoke", []string{serverID}, nil, "success")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": serverID})
		return
	}
	if len(parts) == 5 && parts[4] == "status" && r.Method == http.MethodGet {
		if serverID == types.ServerLocal {
			s.singleJSONAction(w, r, "status")
			return
		}
		server, err := s.store.GetServer(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		writeJSON(w, http.StatusOK, server.Status)
		return
	}
	if len(parts) == 5 && parts[4] == "actions" && r.Method == http.MethodPost {
		s.createAction(w, r, serverID, session)
		return
	}
	if len(parts) == 5 && parts[4] == "nodes" && r.Method == http.MethodPost {
		var fields map[string]any
		if err := decodeBody(r, &fields); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		fields["protocol"] = firstNonEmptyString(fields["protocol"])
		request := actionRequest{Action: "node.add", Args: fields, IdempotencyKey: r.Header.Get("Idempotency-Key")}
		s.enqueueAction(w, serverID, request, session)
		return
	}
	if len(parts) == 5 && parts[4] == "nodes" && r.Method == http.MethodGet {
		if serverID == types.ServerLocal {
			s.singleJSONAction(w, r, "nodes.list")
			return
		}
		server, err := s.store.GetServer(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		if server.NodeSnapshot != nil {
			writeJSON(w, http.StatusOK, server.NodeSnapshot)
		} else {
			writeJSON(w, http.StatusOK, server.Status)
		}
		return
	}
	if len(parts) == 6 && parts[4] == "nodes" && r.Method == http.MethodPatch {
		var fields map[string]any
		if err := decodeBody(r, &fields); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		fields["id"] = parts[5]
		request := actionRequest{Action: "node.set", Args: fields, IdempotencyKey: r.Header.Get("Idempotency-Key")}
		s.enqueueAction(w, serverID, request, session)
		return
	}
	if len(parts) == 6 && parts[4] == "nodes" && r.Method == http.MethodGet {
		if serverID == types.ServerLocal {
			s.jsonAction(w, r, "node.show", map[string]any{"id": parts[5]})
			return
		}
		server, err := s.store.GetServer(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		snapshot := server.NodeSnapshot
		if snapshot == nil {
			snapshot = server.Status
		}
		node, ok := cachedNode(snapshot, parts[5])
		if !ok {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "远程状态快照中没有该节点", nil)
			return
		}
		writeJSON(w, http.StatusOK, node)
		return
	}
	if len(parts) == 7 && parts[4] == "nodes" && parts[6] == "share" && r.Method == http.MethodGet {
		if serverID != types.ServerLocal {
			writeError(w, http.StatusConflict, "AGENT_ASYNC_ONLY", "远程分享链接请通过任务获取", nil)
			return
		}
		var args map[string]any
		if user := r.URL.Query().Get("user"); user != "" {
			args = map[string]any{"id": parts[5], "user_id": user}
		} else {
			args = map[string]any{"id": parts[5]}
		}
		if r.URL.Query().Get("qr") == "1" {
			args["qr"] = true
		}
		result, err := s.runLocal("node.share", args)
		if err != nil {
			writeRunnerError(w, err, result)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"share": strings.TrimSpace(result.Stdout)})
		return
	}
	if len(parts) == 7 && parts[4] == "nodes" && r.Method == http.MethodPost {
		if parts[6] != "enable" && parts[6] != "disable" && parts[6] != "delete" {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "节点操作不存在", nil)
			return
		}
		request := actionRequest{Action: "node." + parts[6], Args: map[string]any{"id": parts[5]}, IdempotencyKey: r.Header.Get("Idempotency-Key")}
		s.enqueueAction(w, serverID, request, session)
		return
	}
	if len(parts) == 7 && parts[4] == "nodes" && parts[6] == "users" && r.Method == http.MethodGet {
		if serverID != types.ServerLocal {
			writeError(w, http.StatusConflict, "AGENT_ASYNC_ONLY", "远程用户列表请通过任务获取", nil)
			return
		}
		s.jsonAction(w, r, "users.list", map[string]any{"node_id": parts[5]})
		return
	}
	if len(parts) == 7 && parts[4] == "nodes" && parts[6] == "users" && r.Method == http.MethodPost {
		var fields map[string]any
		if err := decodeBody(r, &fields); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		fields["node_id"], fields["user_id"] = parts[5], firstNonEmptyString(fields["user_id"])
		s.enqueueAction(w, serverID, actionRequest{Action: "user.add", Args: fields, IdempotencyKey: r.Header.Get("Idempotency-Key")}, session)
		return
	}
	if len(parts) == 9 && parts[4] == "nodes" && parts[6] == "users" && r.Method == http.MethodPost {
		verb := parts[8]
		if verb != "enable" && verb != "disable" && verb != "delete" && verb != "rotate" {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "用户操作不存在", nil)
			return
		}
		s.enqueueAction(w, serverID, actionRequest{Action: "user." + verb, Args: map[string]any{"node_id": parts[5], "user_id": parts[7]}, IdempotencyKey: r.Header.Get("Idempotency-Key")}, session)
		return
	}
	if len(parts) == 5 && parts[4] == "certificates" && r.Method == http.MethodPost {
		var fields map[string]any
		if err := decodeBody(r, &fields); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
			return
		}
		request := actionRequest{Action: "cert.issue", Args: fields, IdempotencyKey: r.Header.Get("Idempotency-Key")}
		s.enqueueAction(w, serverID, request, session)
		return
	}
	if len(parts) == 5 && parts[4] == "backup" && r.Method == http.MethodPost {
		s.enqueueAction(w, serverID, actionRequest{Action: "backup.create", Args: map[string]any{}, IdempotencyKey: r.Header.Get("Idempotency-Key")}, session)
		return
	}
	if len(parts) == 5 && parts[4] == "capabilities" && r.Method == http.MethodGet {
		if serverID == types.ServerLocal {
			s.singleJSONAction(w, r, "core.capabilities")
			return
		}
		server, err := s.store.GetServer(serverID)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		writeJSON(w, http.StatusOK, server.Capabilities)
		return
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器接口不存在", nil)
}

func (s *Server) createAction(w http.ResponseWriter, r *http.Request, serverID string, session types.Session) {
	var request actionRequest
	if err := decodeBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	if request.Args == nil {
		request.Args = map[string]any{}
	}
	s.enqueueAction(w, serverID, request, session)
}

func (s *Server) enqueueAction(w http.ResponseWriter, serverID string, request actionRequest, session types.Session) {
	if sensitiveAction(request.Action) {
		writeError(w, http.StatusBadRequest, "SENSITIVE_ACTION_DIRECT_ONLY", "该操作必须使用专用接口，避免凭据进入任务队列", nil)
		return
	}
	if request.Action == "agent.update" && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以更新 Agent", nil)
		return
	}
	if err := validateQueuedAction(request.Action, request.Args); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	server, err := s.store.GetServer(serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
		return
	}
	if serverID != types.ServerLocal && !server.Online {
		writeError(w, http.StatusConflict, "AGENT_OFFLINE", "服务器当前离线", nil)
		return
	}
	if request.Action == "agent.update" {
		version, _ := request.Args["version"].(string)
		if serverID == types.ServerLocal {
			writeError(w, http.StatusConflict, "AGENT_UPDATE_REMOTE_ONLY", "本机控制端请使用面板更新功能", nil)
			return
		}
		if !supportsAgentUpdate(server) {
			writeError(w, http.StatusConflict, "AGENT_UPDATE_UNSUPPORTED", "该 Agent 尚不支持远程自更新，请先在目标服务器执行一次 sudo sb-web update", nil)
			return
		}
		if server.AgentVersion == version {
			writeError(w, http.StatusConflict, "AGENT_ALREADY_CURRENT", "Agent 已是目标版本", nil)
			return
		}
	}
	if existing, err := s.store.FindTaskByIdempotency(request.IdempotencyKey); err == nil {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	id, err := auth.RandomToken(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "RANDOM_FAILED", err.Error(), nil)
		return
	}
	task := types.Task{ID: "task_" + id, ServerID: serverID, Action: request.Action, Args: request.Args, Status: types.TaskPending, CreatedAt: time.Now().UTC(), IdempotencyKey: request.IdempotencyKey, ExpectedStateDigest: expectedDigestForAction(server, request.Action)}
	if err := s.store.PutTask(task); err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	if serverID == types.ServerLocal {
		go s.executeLocal(task.ID)
	}
	s.recordAudit(session.Username, request.Action, []string{serverID}, []string{task.ID}, "accepted")
	writeJSON(w, http.StatusAccepted, task)
}

func sensitiveAction(action string) bool {
	switch action {
	case "cert.setup-cloudflare", "notify.configure", "tunnel.fixed", "tunnel.set-token", "subscription.revoke", "restore":
		return true
	default:
		return false
	}
}

func validateQueuedAction(action string, args map[string]any) error {
	if action == "agent.update" {
		version, _ := args["version"].(string)
		if len(args) != 1 || !runner.ValidVersion(version) {
			return errors.New("agent.update requires a valid version")
		}
		return nil
	}
	_, err := runner.ActionCommand(action, args)
	return err
}

func supportsAgentUpdate(server types.Server) bool {
	for _, feature := range server.AgentFeatures {
		if feature == "self_update_v1" {
			return true
		}
	}
	return false
}

func firstNonEmptyString(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func expectedDigest(server types.Server) string {
	if server.ID == types.ServerLocal {
		return ""
	}
	return server.StateDigest
}

func expectedDigestForAction(server types.Server, action string) string {
	if action == "agent.update" {
		return ""
	}
	return expectedDigest(server)
}

func cachedNode(status any, id string) (map[string]any, bool) {
	var nodes []any
	switch value := status.(type) {
	case []any:
		nodes = value
	case map[string]any:
		if value, ok := value["nodes"].([]any); ok {
			nodes = value
		}
	}
	for _, item := range nodes {
		node, ok := item.(map[string]any)
		if ok && fmt.Sprint(node["id"]) == id {
			return node, true
		}
	}
	return nil, false
}

func (s *Server) executeLocal(id string) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	task, err := s.store.ClaimTask(id)
	if err != nil {
		return
	}
	if stop, _ := s.store.BatchShouldStop(task.BatchID, s.cfg.Tasks.FailureStopPct); stop {
		s.finishTask(id, false, "", "batch stopped after reaching failure threshold")
		return
	}
	result, err := s.runLocal(task.Action, task.Args)
	if err != nil {
		s.finishTask(id, false, result.Stdout, redact(result.Stderr+"\n"+err.Error()))
		return
	}
	s.finishTask(id, true, redact(result.Stdout), redact(result.Stderr))
}

func (s *Server) finishTask(id string, success bool, output, problem string) {
	_, _ = s.store.UpdateTask(id, func(task *types.Task) error {
		now := time.Now().UTC()
		task.FinishedAt = &now
		task.Output = truncate(redact(output), 32768)
		task.Error = truncate(redact(problem), 8192)
		if task.CancelRequested {
			task.Status = types.TaskCanceled
			if task.Error == "" {
				task.Error = "task canceled"
			}
		} else if success {
			task.Status = types.TaskSuccess
		} else {
			task.Status = types.TaskFailed
		}
		return nil
	})
}

func (s *Server) tasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET", nil)
		return
	}
	tasks, err := s.store.ListTasks(100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) taskAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "tasks" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "任务接口不存在", nil)
		return
	}
	id := parts[3]
	task, err := s.store.GetTask(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "任务不存在", nil)
		return
	}
	if len(parts) == 4 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, task)
		return
	}
	if len(parts) != 5 || r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 GET、POST /cancel 或 /retry", nil)
		return
	}
	if task.Action == "agent.update" && s.auth.Role(session.Username) != "admin" {
		writeError(w, http.StatusForbidden, "ROLE_FORBIDDEN", "只有管理员可以管理 Agent 更新任务", nil)
		return
	}
	switch parts[4] {
	case "cancel":
		updated, cancelErr := s.store.CancelTask(id)
		if cancelErr != nil {
			writeError(w, http.StatusConflict, "TASK_NOT_CANCELLABLE", cancelErr.Error(), nil)
			return
		}
		s.recordAudit(session.Username, "task.cancel", []string{updated.ServerID}, []string{updated.ID}, "accepted")
		writeJSON(w, http.StatusAccepted, updated)
	case "retry":
		server, serverErr := s.store.GetServer(task.ServerID)
		if serverErr != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "服务器不存在", nil)
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			key = "retry_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		created, retryErr := s.store.CloneTask(id, key, expectedDigestForAction(server, task.Action))
		if retryErr != nil {
			writeError(w, http.StatusConflict, "TASK_NOT_RETRYABLE", retryErr.Error(), nil)
			return
		}
		if created.ServerID == types.ServerLocal {
			go s.executeLocal(created.ID)
		}
		s.recordAudit(session.Username, "task.retry", []string{created.ServerID}, []string{created.ID}, "accepted")
		writeJSON(w, http.StatusAccepted, created)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "任务操作不存在", nil)
	}
}

type registerRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	Region    string `json:"region"`
	Arch      string `json:"arch"`
}

func (s *Server) agentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
		return
	}
	var request registerRequest
	if err := decodeBody(r, &request); err != nil || request.Token == "" || request.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "token 和 public_key 必填", nil)
		return
	}
	hash := auth.HashEnrollmentToken(request.Token)
	enrollment, err := s.store.GetEnrollment(hash)
	if err != nil || enrollment.Used || enrollment.ExpiresAt.Before(time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "ENROLLMENT_INVALID", "加入令牌无效或已过期", nil)
		return
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(request.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "public_key 不是有效 Ed25519 公钥", nil)
		return
	}
	id, err := auth.RandomToken(10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "RANDOM_FAILED", err.Error(), nil)
		return
	}
	server := types.Server{ID: "srv_" + id, Name: firstNonEmpty(request.Name, "远程服务器"), Address: request.Address, Region: request.Region, Arch: request.Arch, AgentPublicKey: request.PublicKey, Online: true, LastSeen: time.Now().UTC()}
	if err := s.store.ConsumeEnrollment(hash, server); err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
		return
	}
	s.recordAudit("enrollment", "agent.register", []string{server.ID}, nil, "success")
	certPEM, keyPEM, certErr := s.issueAgentCertificate(server.ID)
	if certErr != nil {
		writeError(w, http.StatusInternalServerError, "MTLS_ISSUE_FAILED", certErr.Error(), nil)
		return
	}
	response := map[string]any{"server_id": server.ID, "heartbeat_interval": "30s"}
	if len(certPEM) > 0 {
		response["client_certificate"] = normalizePEM(certPEM)
		response["client_key"] = normalizePEM(keyPEM)
		response["client_ca"] = normalizePEM(s.agentCA.PEM)
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) agentAPI(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	server, ok := s.verifyAgent(r, body)
	if !ok {
		writeError(w, http.StatusUnauthorized, "AGENT_AUTH_FAILED", "Agent 身份验证失败", nil)
		return
	}
	if s.cfg.TLS.RequireAgentMTLS && (r.TLS == nil || !s.verifyAgentMTLS(server.ID, r.TLS.PeerCertificates)) {
		writeError(w, http.StatusUnauthorized, "AGENT_MTLS_REQUIRED", "需要有效的 Agent 客户端证书", nil)
		return
	}
	switch r.URL.Path {
	case "/api/v1/agent/heartbeat":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
			return
		}
		var heartbeat struct {
			AgentVersion     string   `json:"agent_version"`
			AgentFeatures    []string `json:"agent_features"`
			SBManagerVersion string   `json:"sb_manager_version"`
			CoreVersion      string   `json:"core_version"`
			Backend          string   `json:"backend"`
			Status           any      `json:"status"`
			Capabilities     any      `json:"capabilities"`
			NodeSnapshot     any      `json:"node_snapshot"`
			StateDigest      string   `json:"state_digest"`
			StateSchema      int      `json:"state_schema"`
		}
		if json.Unmarshal(body, &heartbeat) != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "心跳 JSON 无效", nil)
			return
		}
		server.AgentVersion, server.AgentFeatures, server.SBManagerVersion, server.CoreVersion, server.Backend = heartbeat.AgentVersion, heartbeat.AgentFeatures, heartbeat.SBManagerVersion, heartbeat.CoreVersion, heartbeat.Backend
		server.Status, server.Capabilities, server.NodeSnapshot, server.StateDigest, server.StateSchema, server.Online, server.LastSeen = heartbeat.Status, heartbeat.Capabilities, heartbeat.NodeSnapshot, heartbeat.StateDigest, heartbeat.StateSchema, true, time.Now().UTC()
		if err := s.store.PutServer(server); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		if err := s.store.ConfirmAgentUpdate(server.ID, heartbeat.AgentVersion); err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "/api/v1/agent/poll":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
			return
		}
		task, err := s.store.ClaimPendingTask(server.ID, s.cfg.Tasks.FailureStopPct)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{"task": nil})
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"task": task})
	case "/api/v1/agent/result":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
			return
		}
		var result struct {
			TaskID string `json:"task_id"`
			Status string `json:"status"`
			Output string `json:"output"`
			Error  string `json:"error"`
		}
		if json.Unmarshal(body, &result) != nil || result.TaskID == "" || (result.Status != types.TaskSuccess && result.Status != types.TaskFailed) {
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", "任务结果无效", nil)
			return
		}
		task, err := s.store.GetTask(result.TaskID)
		if err != nil || task.ServerID != server.ID {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "任务不存在或目标不匹配", nil)
			return
		}
		_, err = s.store.UpdateTask(result.TaskID, func(task *types.Task) error {
			now := time.Now().UTC()
			if task.CancelRequested {
				task.Status = types.TaskCanceled
				if result.Error == "" {
					result.Error = "task canceled"
				}
			} else {
				task.Status = result.Status
			}
			task.FinishedAt = &now
			task.Output, task.Error = truncate(redact(result.Output), 32768), truncate(redact(result.Error), 8192)
			return nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "/api/v1/agent/rotate":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "只支持 POST", nil)
			return
		}
		if s.agentCA == nil {
			writeError(w, http.StatusConflict, "MTLS_DISABLED", "控制端未配置 Agent mTLS", nil)
			return
		}
		certPEM, keyPEM, issueErr := s.issueAgentCertificate(server.ID)
		if issueErr != nil {
			writeError(w, http.StatusInternalServerError, "MTLS_ISSUE_FAILED", issueErr.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"client_certificate": normalizePEM(certPEM), "client_key": normalizePEM(keyPEM), "client_ca": normalizePEM(s.agentCA.PEM)})
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Agent 接口不存在", nil)
	}
}

func (s *Server) verifyAgent(r *http.Request, body []byte) (types.Server, bool) {
	id := r.Header.Get("X-Agent-ID")
	timestamp, err := strconv.ParseInt(r.Header.Get("X-Agent-Timestamp"), 10, 64)
	if id == "" || err != nil || time.Since(time.Unix(timestamp, 0)) > 2*time.Minute || time.Until(time.Unix(timestamp, 0)) > 2*time.Minute {
		return types.Server{}, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Agent-Signature"))
	if err != nil {
		return types.Server{}, false
	}
	server, err := s.store.GetServer(id)
	if err != nil {
		return types.Server{}, false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(server.AgentPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return types.Server{}, false
	}
	message := r.Method + "\n" + r.URL.Path + "\n" + r.Header.Get("X-Agent-Timestamp") + "\n" + string(body)
	return server, ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature)
}

func (s *Server) runLocal(action string, args map[string]any) (runner.Result, error) {
	if s.cfg.HelperSocket != "" {
		if _, err := os.Stat(s.cfg.HelperSocket); err == nil {
			return helper.Client{Socket: s.cfg.HelperSocket, Timeout: s.cfg.Tasks.DefaultTimeout}.Run(context.Background(), action, args)
		}
	}
	command, err := runner.ActionCommand(action, args)
	if err != nil {
		return runner.Result{}, err
	}
	return s.runner.Run(context.Background(), command...)
}

func writeRunnerError(w http.ResponseWriter, err error, result runner.Result) {
	status := http.StatusBadGateway
	code := "COMMAND_FAILED"
	if result.TimedOut {
		status, code = http.StatusGatewayTimeout, "COMMAND_TIMEOUT"
	}
	writeError(w, status, code, err.Error(), map[string]any{"exit_code": result.ExitCode, "stderr": redact(result.Stderr)})
}

func decodeBody(r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(nilResponseWriter{}, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// nilResponseWriter is only used so MaxBytesReader can enforce a request limit.
type nilResponseWriter struct{}

func (nilResponseWriter) Header() http.Header       { return make(http.Header) }
func (nilResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (nilResponseWriter) WriteHeader(int)           {}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "\n[truncated]"
}

func redact(value string) string {
	return secretJSONPattern.ReplaceAllString(value, `"$1":"[REDACTED]"`)
}

var secretJSONPattern = regexp.MustCompile(`(?i)"(password|token|psk|private_key|uuid)"\s*:\s*"[^"]*"`)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
