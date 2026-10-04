package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/types"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires_at TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, last_seen TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, status TEXT NOT NULL, batch_id TEXT NOT NULL DEFAULT '', idempotency_key TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_tasks_server_status ON tasks(server_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_batch ON tasks(batch_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_idempotency ON tasks(idempotency_key) WHERE idempotency_key <> '';
CREATE TABLE IF NOT EXISTS enrollments (hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL, used INTEGER NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS metrics (recorded_at TEXT PRIMARY KEY, data BLOB NOT NULL);
PRAGMA user_version=1;
`

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize sqlite schema: %w", err)
	}
	store := &Store{db: db}
	if err := store.RecoverRunningTasks(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("recover running tasks: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Backup(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("backup destination is empty")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, destination)
	return err
}
func encode(value any) ([]byte, error)    { return json.Marshal(value) }
func decode(data []byte, value any) error { return json.Unmarshal(data, value) }
func stamp(value time.Time) string        { return value.UTC().Format(time.RFC3339Nano) }

func (s *Store) PutUser(user types.User) error {
	data, err := encode(user)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(username,data) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET data=excluded.data`, user.Username, data)
	return err
}
func (s *Store) GetUser(username string) (types.User, error) {
	var data []byte
	var value types.User
	err := s.db.QueryRow(`SELECT data FROM users WHERE username=?`, username).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}
func (s *Store) HasUsers() (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count > 0, err
}

func (s *Store) ListUsers() ([]types.User, error) {
	rows, err := s.db.Query(`SELECT data FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []types.User{}
	for rows.Next() {
		var data []byte
		var user types.User
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decode(data, &user); err != nil {
			return nil, err
		}
		user.Hash = ""
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) DeleteUser(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM users WHERE username=?`, username); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id,data FROM sessions`)
	if err != nil {
		return err
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			rows.Close()
			return err
		}
		var session types.Session
		if decode(data, &session) == nil && session.Username == username {
			sessionIDs = append(sessionIDs, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range sessionIDs {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PutAPIToken(token types.APIToken) error {
	data, err := encode(token)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO api_tokens(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, token.ID, data)
	return err
}

func (s *Store) GetAPIToken(id string) (types.APIToken, error) {
	var data []byte
	var token types.APIToken
	err := s.db.QueryRow(`SELECT data FROM api_tokens WHERE id=?`, id).Scan(&data)
	if err == nil {
		err = decode(data, &token)
	}
	return token, err
}

func (s *Store) ListAPITokens() ([]types.APIToken, error) {
	rows, err := s.db.Query(`SELECT data FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []types.APIToken{}
	for rows.Next() {
		var data []byte
		var token types.APIToken
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decode(data, &token); err != nil {
			return nil, err
		}
		token.Hash = ""
		values = append(values, token)
	}
	return values, rows.Err()
}

func (s *Store) DeleteAPIToken(id string) error {
	_, err := s.db.Exec(`DELETE FROM api_tokens WHERE id=?`, id)
	return err
}

func (s *Store) PutMetric(recorded time.Time, value any) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO metrics(recorded_at,data) VALUES(?,?) ON CONFLICT(recorded_at) DO UPDATE SET data=excluded.data`, stamp(recorded), data)
	return err
}

func (s *Store) ListMetrics(since time.Time, limit int) ([]map[string]any, error) {
	if limit < 1 || limit > 10000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT recorded_at,data FROM metrics WHERE recorded_at>=? ORDER BY recorded_at DESC LIMIT ?`, stamp(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []map[string]any{}
	for rows.Next() {
		var recorded string
		var data []byte
		var value map[string]any
		if err := rows.Scan(&recorded, &data); err != nil {
			return nil, err
		}
		if err := decode(data, &value); err != nil {
			return nil, err
		}
		value["recorded_at"] = recorded
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) PruneMetrics(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM metrics WHERE recorded_at<?`, stamp(before))
	return err
}

func (s *Store) FindAPITokenByHash(hash string) (types.APIToken, error) {
	rows, err := s.db.Query(`SELECT data FROM api_tokens`)
	if err != nil {
		return types.APIToken{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		var token types.APIToken
		if err := rows.Scan(&data); err != nil {
			return types.APIToken{}, err
		}
		if err := decode(data, &token); err != nil {
			return types.APIToken{}, err
		}
		if token.Hash == hash {
			return token, nil
		}
	}
	return types.APIToken{}, sql.ErrNoRows
}

func (s *Store) PutSession(value types.Session) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO sessions(id,expires_at,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data`, value.ID, stamp(value.ExpiresAt), data)
	return err
}
func (s *Store) GetSession(id string) (types.Session, error) {
	var data []byte
	var value types.Session
	err := s.db.QueryRow(`SELECT data FROM sessions WHERE id=?`, id).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) PutServer(value types.Server) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO servers(id,last_seen,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,data=excluded.data`, value.ID, stamp(value.LastSeen), data)
	return err
}
func (s *Store) GetServer(id string) (types.Server, error) {
	var data []byte
	var value types.Server
	err := s.db.QueryRow(`SELECT data FROM servers WHERE id=?`, id).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}
func (s *Store) ListServers() ([]types.Server, error) {
	rows, err := s.db.Query(`SELECT data FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []types.Server{}
	for rows.Next() {
		var data []byte
		var value types.Server
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decode(data, &value); err != nil {
			return nil, err
		}
		value.AgentPublicKey = ""
		values = append(values, value)
	}
	return values, rows.Err()
}
func (s *Store) DeleteServer(id string) error {
	_, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

func taskArgs(task types.Task) (string, string, string, string, string, []byte, error) {
	data, err := encode(task)
	return task.ServerID, task.Status, task.BatchID, task.IdempotencyKey, stamp(task.CreatedAt), data, err
}
func putTask(execer interface {
	Exec(string, ...any) (sql.Result, error)
}, task types.Task) error {
	serverID, status, batchID, idem, created, data, err := taskArgs(task)
	if err != nil {
		return err
	}
	_, err = execer.Exec(`INSERT INTO tasks(id,server_id,status,batch_id,idempotency_key,created_at,data) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,status=excluded.status,batch_id=excluded.batch_id,idempotency_key=excluded.idempotency_key,created_at=excluded.created_at,data=excluded.data`, task.ID, serverID, status, batchID, idem, created, data)
	return err
}
func (s *Store) PutTask(task types.Task) error { return putTask(s.db, task) }

func (s *Store) ListPendingTaskIDs(serverID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM tasks WHERE server_id=? AND status=? ORDER BY created_at`, serverID, types.TaskPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClaimTask atomically moves one pending task to running. It is used by local
// workers so duplicate wake-ups cannot execute the same task twice.
func (s *Store) ClaimTask(id string) (types.Task, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return types.Task{}, err
	}
	defer tx.Rollback()
	var data []byte
	var task types.Task
	if err := tx.QueryRow(`SELECT data FROM tasks WHERE id=?`, id).Scan(&data); err != nil {
		return task, err
	}
	if err := decode(data, &task); err != nil {
		return task, err
	}
	if task.Status != types.TaskPending || task.CancelRequested {
		return task, sql.ErrNoRows
	}
	now := time.Now().UTC()
	task.Status = types.TaskRunning
	task.StartedAt = &now
	if err := putTask(tx, task); err != nil {
		return task, err
	}
	if err := tx.Commit(); err != nil {
		return task, err
	}
	return task, nil
}

// RecoverRunningTasks makes controller restarts resumable. A task claimed by
// an Agent or local worker before a crash is safely returned to the pending
// queue; the original attempt and an explanatory error remain in its record.
func (s *Store) RecoverRunningTasks() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT data FROM tasks WHERE status=?`, types.TaskRunning)
	if err != nil {
		return err
	}
	var tasks []types.Task
	for rows.Next() {
		var data []byte
		var task types.Task
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decode(data, &task); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, task := range tasks {
		task.Status = types.TaskPending
		task.StartedAt = nil
		task.Error = "controller restarted; task requeued"
		if err := putTask(tx, task); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) GetTask(id string) (types.Task, error) {
	var data []byte
	var value types.Task
	err := s.db.QueryRow(`SELECT data FROM tasks WHERE id=?`, id).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}
func (s *Store) UpdateTask(id string, update func(*types.Task) error) (types.Task, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return types.Task{}, err
	}
	defer tx.Rollback()
	var data []byte
	var value types.Task
	if err := tx.QueryRow(`SELECT data FROM tasks WHERE id=?`, id).Scan(&data); err != nil {
		return value, err
	}
	if err := decode(data, &value); err != nil {
		return value, err
	}
	if err := update(&value); err != nil {
		return value, err
	}
	if err := putTask(tx, value); err != nil {
		return value, err
	}
	return value, tx.Commit()
}
func (s *Store) ListTasks(limit int) ([]types.Task, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT data FROM (SELECT data,created_at FROM tasks ORDER BY created_at DESC LIMIT ?) ORDER BY created_at ASC`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []types.Task{}
	for rows.Next() {
		var data []byte
		var value types.Task
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decode(data, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
func (s *Store) FindTaskByIdempotency(key string) (types.Task, error) {
	if key == "" {
		return types.Task{}, sql.ErrNoRows
	}
	var data []byte
	var value types.Task
	err := s.db.QueryRow(`SELECT data FROM tasks WHERE idempotency_key=?`, key).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}

// CancelTask marks a pending task as canceled. A running task is marked for
// cancellation and its executor will record the final canceled state when it
// returns; this keeps the database transition atomic without killing an
// arbitrary process from the controller.
func (s *Store) CancelTask(id string) (types.Task, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return types.Task{}, err
	}
	defer tx.Rollback()
	var data []byte
	var task types.Task
	if err := tx.QueryRow(`SELECT data FROM tasks WHERE id=?`, id).Scan(&data); err != nil {
		return task, err
	}
	if err := decode(data, &task); err != nil {
		return task, err
	}
	switch task.Status {
	case types.TaskPending:
		now := time.Now().UTC()
		task.Status = types.TaskCanceled
		task.CancelRequested = true
		task.FinishedAt = &now
	case types.TaskRunning:
		task.CancelRequested = true
	default:
		return task, errors.New("task is already finished")
	}
	if err := putTask(tx, task); err != nil {
		return task, err
	}
	if err := tx.Commit(); err != nil {
		return task, err
	}
	return task, nil
}

func (s *Store) CloneTask(id, idempotencyKey string, expectedDigest string) (types.Task, error) {
	original, err := s.GetTask(id)
	if err != nil {
		return types.Task{}, err
	}
	if original.Status != types.TaskFailed && original.Status != types.TaskCanceled {
		return types.Task{}, errors.New("only failed or canceled tasks can be retried")
	}
	if idempotencyKey == "" {
		return types.Task{}, errors.New("retry idempotency key is required")
	}
	if existing, findErr := s.FindTaskByIdempotency(idempotencyKey); findErr == nil {
		return existing, nil
	}
	randomID := fmt.Sprintf("retry_%d", time.Now().UnixNano())
	task := types.Task{ID: randomID, ServerID: original.ServerID, Action: original.Action, Args: original.Args, Status: types.TaskPending, CreatedAt: time.Now().UTC(), IdempotencyKey: idempotencyKey, ExpectedStateDigest: expectedDigest, Attempt: original.Attempt + 1, RetryOf: original.ID}
	if err := s.PutTask(task); err != nil {
		return types.Task{}, err
	}
	return task, nil
}
func (s *Store) BatchShouldStop(batchID string, threshold int) (bool, error) {
	if batchID == "" || threshold <= 0 || threshold > 100 {
		return false, nil
	}
	var completed, failed int
	err := s.db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status IN ('success','failed','canceled') THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) FROM tasks WHERE batch_id=?`, batchID).Scan(&completed, &failed)
	return completed > 0 && failed*100/completed >= threshold, err
}
func (s *Store) ClaimPendingTask(serverID string, failureStopPercent int) (types.Task, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return types.Task{}, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT data FROM tasks WHERE server_id=? AND status=? ORDER BY created_at`, serverID, types.TaskPending)
	if err != nil {
		return types.Task{}, err
	}
	candidates := []types.Task{}
	for rows.Next() {
		var data []byte
		var task types.Task
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return types.Task{}, err
		}
		if err := decode(data, &task); err != nil {
			rows.Close()
			return types.Task{}, err
		}
		candidates = append(candidates, task)
	}
	rows.Close()
	for _, task := range candidates {
		var completed, failed int
		if task.BatchID != "" && failureStopPercent > 0 {
			if err := tx.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status IN ('success','failed','canceled') THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) FROM tasks WHERE batch_id=?`, task.BatchID).Scan(&completed, &failed); err != nil {
				return types.Task{}, err
			}
			if completed > 0 && failed*100/completed >= failureStopPercent {
				now := time.Now().UTC()
				task.Status, task.Error, task.FinishedAt = types.TaskFailed, "batch stopped after reaching failure threshold", &now
				if err := putTask(tx, task); err != nil {
					return types.Task{}, err
				}
				continue
			}
		}
		now := time.Now().UTC()
		task.Status, task.StartedAt = types.TaskRunning, &now
		if err := putTask(tx, task); err != nil {
			return types.Task{}, err
		}
		if err := tx.Commit(); err != nil {
			return types.Task{}, err
		}
		return task, nil
	}
	if err := tx.Commit(); err != nil {
		return types.Task{}, err
	}
	return types.Task{}, sql.ErrNoRows
}

// ConfirmAgentUpdate completes an update task when a restarted Agent reports
// the requested version. Pending tasks are included so controller restarts do
// not cause an already-installed update to run twice.
func (s *Store) ConfirmAgentUpdate(serverID, version string) error {
	if serverID == "" || version == "" {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT data FROM tasks WHERE server_id=? AND status IN (?,?)`, serverID, types.TaskPending, types.TaskRunning)
	if err != nil {
		return err
	}
	tasks := []types.Task{}
	for rows.Next() {
		var data []byte
		var task types.Task
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decode(data, &task); err != nil {
			rows.Close()
			return err
		}
		if target, _ := task.Args["version"].(string); task.Action == "agent.update" && target == version {
			tasks = append(tasks, task)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, task := range tasks {
		now := time.Now().UTC()
		task.FinishedAt = &now
		task.Error = ""
		task.Output = "Agent heartbeat confirmed version " + version
		if task.CancelRequested {
			task.Status = types.TaskCanceled
			task.Error = "task canceled after Agent update"
		} else {
			task.Status = types.TaskSuccess
		}
		if err := putTask(tx, task); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PutEnrollment(key string, token types.EnrollmentToken) error {
	data, err := encode(token)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO enrollments(hash,expires_at,used,data) VALUES(?,?,?,?) ON CONFLICT(hash) DO UPDATE SET expires_at=excluded.expires_at,used=excluded.used,data=excluded.data`, key, stamp(token.ExpiresAt), token.Used, data)
	return err
}
func (s *Store) GetEnrollment(key string) (types.EnrollmentToken, error) {
	var data []byte
	var value types.EnrollmentToken
	err := s.db.QueryRow(`SELECT data FROM enrollments WHERE hash=?`, key).Scan(&data)
	if err == nil {
		err = decode(data, &value)
	}
	return value, err
}
func (s *Store) MarkEnrollmentUsed(key string) error {
	token, err := s.GetEnrollment(key)
	if err != nil {
		return err
	}
	token.Used = true
	return s.PutEnrollment(key, token)
}
func (s *Store) ConsumeEnrollment(key string, server types.Server) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var data []byte
	var token types.EnrollmentToken
	if err := tx.QueryRow(`SELECT data FROM enrollments WHERE hash=?`, key).Scan(&data); err != nil {
		return err
	}
	if err := decode(data, &token); err != nil {
		return err
	}
	if token.Used || token.ExpiresAt.Before(time.Now().UTC()) {
		return errors.New("enrollment token is used or expired")
	}
	token.Used = true
	tokenData, err := encode(token)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE enrollments SET used=1,data=? WHERE hash=? AND used=0`, tokenData, key); err != nil {
		return err
	}
	serverData, err := encode(server)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO servers(id,last_seen,data) VALUES(?,?,?)`, server.ID, stamp(server.LastSeen), serverData); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) PutAudit(value types.AuditEvent) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO audit(id,created_at,data) VALUES(?,?,?)`, value.ID, stamp(value.CreatedAt), data)
	return err
}
func (s *Store) ListAudit(limit int) ([]types.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT data FROM (SELECT data,created_at FROM audit ORDER BY created_at DESC LIMIT ?) ORDER BY created_at ASC`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []types.AuditEvent{}
	for rows.Next() {
		var data []byte
		var value types.AuditEvent
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decode(data, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
