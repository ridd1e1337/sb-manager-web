package types

import "time"

const (
	ServerLocal  = "local"
	TaskPending  = "pending"
	TaskRunning  = "running"
	TaskSuccess  = "success"
	TaskFailed   = "failed"
	TaskCanceled = "canceled"
)

type Server struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Address            string    `json:"address,omitempty"`
	Region             string    `json:"region,omitempty"`
	Tags               []string  `json:"tags,omitempty"`
	AgentVersion       string    `json:"agent_version,omitempty"`
	AgentFeatures      []string  `json:"agent_features,omitempty"`
	SBManagerVersion   string    `json:"sb_manager_version,omitempty"`
	CoreVersion        string    `json:"core_version,omitempty"`
	Arch               string    `json:"arch,omitempty"`
	Backend            string    `json:"backend,omitempty"`
	Online             bool      `json:"online"`
	LastSeen           time.Time `json:"last_seen,omitempty"`
	Status             any       `json:"status,omitempty"`
	Capabilities       any       `json:"capabilities,omitempty"`
	NodeSnapshot       any       `json:"node_snapshot,omitempty"`
	AgentPublicKey     string    `json:"agent_public_key,omitempty"`
	AgentIdentityState string    `json:"agent_identity_state,omitempty"`
	StateDigest        string    `json:"state_digest,omitempty"`
	StateSchema        int       `json:"state_schema,omitempty"`
}

type Task struct {
	ID                  string         `json:"id"`
	ServerID            string         `json:"server_id"`
	Action              string         `json:"action"`
	Args                map[string]any `json:"args,omitempty"`
	Status              string         `json:"status"`
	Output              string         `json:"output,omitempty"`
	Error               string         `json:"error,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	StartedAt           *time.Time     `json:"started_at,omitempty"`
	FinishedAt          *time.Time     `json:"finished_at,omitempty"`
	IdempotencyKey      string         `json:"idempotency_key,omitempty"`
	BatchID             string         `json:"batch_id,omitempty"`
	ExpectedStateDigest string         `json:"expected_state_digest,omitempty"`
	CancelRequested     bool           `json:"cancel_requested,omitempty"`
	Attempt             int            `json:"attempt,omitempty"`
	RetryOf             string         `json:"retry_of,omitempty"`
}

type EnrollmentToken struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type User struct {
	Username           string    `json:"username"`
	Hash               string    `json:"hash"`
	Created            time.Time `json:"created"`
	Role               string    `json:"role,omitempty"`
	TOTPSecret         string    `json:"totp_secret,omitempty"`
	TOTPEnabled        bool      `json:"totp_enabled,omitempty"`
	RecoveryCodeHashes []string  `json:"recovery_code_hashes,omitempty"`
}

type APIToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	Role      string     `json:"role"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	CSRF      string    `json:"csrf"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	ServerIDs []string  `json:"server_ids,omitempty"`
	TaskIDs   []string  `json:"task_ids,omitempty"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}
