package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/storage"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
	"golang.org/x/crypto/argon2"
)

type Manager struct{ store *storage.Store }

type InitialCredential struct {
	Username string
	Password string
}

func New(store *storage.Store) *Manager { return &Manager{store: store} }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func RandomToken(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=1,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 1, 64*1024, 2, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func (m *Manager) EnsureOwner() (InitialCredential, bool, error) {
	has, err := m.store.HasUsers()
	if err != nil || has {
		return InitialCredential{}, false, err
	}
	usernameToken, err := RandomToken(6)
	if err != nil {
		return InitialCredential{}, false, err
	}
	username := "owner-" + strings.ToLower(usernameToken)
	password, err := RandomToken(18)
	if err != nil {
		return InitialCredential{}, false, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return InitialCredential{}, false, err
	}
	err = m.store.PutUser(types.User{Username: username, Hash: hash, Created: time.Now().UTC(), Role: "admin"})
	return InitialCredential{Username: username, Password: password}, true, err
}

// EnsureAdmin is kept for integrations built against the initial alpha API.
// New installations still receive the random owner username; callers using
// this compatibility helper should obtain the username from ListUsers.
func (m *Manager) EnsureAdmin() (string, bool, error) {
	credential, created, err := m.EnsureOwner()
	return credential.Password, created, err
}

func (m *Manager) CreateUser(username, password, role string) error {
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return errors.New("invalid username")
	}
	if role == "" {
		role = "viewer"
	}
	if !validRole(role) {
		return errors.New("invalid role")
	}
	if _, err := m.store.GetUser(username); err == nil {
		return errors.New("username already exists")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return m.store.PutUser(types.User{Username: username, Hash: hash, Created: time.Now().UTC(), Role: role})
}

func (m *Manager) Role(username string) string {
	user, err := m.store.GetUser(username)
	if err != nil || user.Role == "" {
		return "admin"
	}
	return user.Role
}

func (m *Manager) SetRole(username, role string) error {
	if !validRole(role) {
		return errors.New("invalid role")
	}
	user, err := m.store.GetUser(username)
	if err != nil {
		return err
	}
	user.Role = role
	return m.store.PutUser(user)
}

func (m *Manager) AdminUsername() (string, error) {
	users, err := m.store.ListUsers()
	if err != nil {
		return "", err
	}
	for _, user := range users {
		if m.Role(user.Username) == "admin" {
			return user.Username, nil
		}
	}
	return "", errors.New("no administrator account exists")
}

func validUsername(username string) bool {
	if len(username) < 1 || len(username) > 64 {
		return false
	}
	for _, char := range username {
		if !(char == '-' || char == '_' || char == '.' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func validRole(role string) bool {
	return role == "admin" || role == "operator" || role == "viewer"
}

func (m *Manager) Authenticate(username, password string) bool {
	user, err := m.store.GetUser(username)
	return err == nil && VerifyPassword(user.Hash, password)
}

func GenerateTOTPSecret() (string, error) {
	data, err := randomBytes(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data), nil
}

func TOTPCode(secret string, at time.Time) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(raw) < 10 {
		return "", errors.New("invalid TOTP secret")
	}
	counter := uint64(at.Unix() / 30)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	hasher := hmac.New(sha1.New, raw)
	_, _ = hasher.Write(message[:])
	digest := hasher.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	number := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", number%1000000), nil
}

func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		candidate, err := TOTPCode(secret, at.Add(time.Duration(offset)*30*time.Second))
		if err == nil && subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func RecoveryCodeHash(code string) string {
	return HashEnrollmentToken(strings.TrimSpace(code))
}

func ConsumeRecoveryCode(user *types.User, code string) bool {
	hash := RecoveryCodeHash(code)
	for index, candidate := range user.RecoveryCodeHashes {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(hash)) == 1 {
			user.RecoveryCodeHashes = append(user.RecoveryCodeHashes[:index], user.RecoveryCodeHashes[index+1:]...)
			return true
		}
	}
	return false
}

func (m *Manager) SetupTOTP(username string) (string, string, error) {
	user, err := m.store.GetUser(username)
	if err != nil {
		return "", "", err
	}
	if user.TOTPEnabled {
		return "", "", errors.New("TOTP is already enabled")
	}
	if user.TOTPSecret != "" {
		uri := "otpauth://totp/sb-manager-web:" + username + "?secret=" + user.TOTPSecret + "&issuer=sb-manager-web&algorithm=SHA1&digits=6&period=30"
		return user.TOTPSecret, uri, nil
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	user.TOTPSecret = secret
	if err := m.store.PutUser(user); err != nil {
		return "", "", err
	}
	uri := "otpauth://totp/sb-manager-web:" + username + "?secret=" + secret + "&issuer=sb-manager-web&algorithm=SHA1&digits=6&period=30"
	return secret, uri, nil
}

func (m *Manager) EnableTOTP(username, code string) ([]string, error) {
	user, err := m.store.GetUser(username)
	if err != nil {
		return nil, err
	}
	if user.TOTPSecret == "" || !VerifyTOTP(user.TOTPSecret, code, time.Now()) {
		return nil, errors.New("invalid TOTP code")
	}
	codes := make([]string, 8)
	hashes := make([]string, 0, len(codes))
	for index := range codes {
		value, err := RandomToken(6)
		if err != nil {
			return nil, err
		}
		codes[index] = strings.ToUpper(value[:8])
		hashes = append(hashes, RecoveryCodeHash(codes[index]))
	}
	user.TOTPEnabled, user.RecoveryCodeHashes = true, hashes
	if err := m.store.PutUser(user); err != nil {
		return nil, err
	}
	return codes, nil
}

func (m *Manager) DisableTOTP(username, code string) error {
	user, err := m.store.GetUser(username)
	if err != nil {
		return err
	}
	if user.TOTPEnabled && !VerifyTOTP(user.TOTPSecret, code, time.Now()) && !ConsumeRecoveryCode(&user, code) {
		return errors.New("invalid TOTP code")
	}
	user.TOTPEnabled, user.TOTPSecret, user.RecoveryCodeHashes = false, "", nil
	return m.store.PutUser(user)
}

func (m *Manager) AuthenticateAPIToken(raw string) (types.APIToken, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return types.APIToken{}, false
	}
	token, err := m.store.FindAPITokenByHash(HashEnrollmentToken(raw))
	if err != nil {
		return types.APIToken{}, false
	}
	now := time.Now().UTC()
	token.LastUsed = &now
	_ = m.store.PutAPIToken(token)
	token.Hash = ""
	return token, true
}

func (m *Manager) CreateAPIToken(name, role string) (types.APIToken, string, error) {
	if !validRole(role) || strings.TrimSpace(name) == "" || len(name) > 64 {
		return types.APIToken{}, "", errors.New("invalid API token name or role")
	}
	raw, err := RandomToken(32)
	if err != nil {
		return types.APIToken{}, "", err
	}
	id, err := RandomToken(8)
	if err != nil {
		return types.APIToken{}, "", err
	}
	token := types.APIToken{ID: "tok_" + id, Name: strings.TrimSpace(name), Role: role, Hash: HashEnrollmentToken(raw), CreatedAt: time.Now().UTC()}
	if err := m.store.PutAPIToken(token); err != nil {
		return types.APIToken{}, "", err
	}
	token.Hash = ""
	return token, raw, nil
}

func (m *Manager) SetPassword(username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	user, getErr := m.store.GetUser(username)
	if getErr != nil {
		return getErr
	}
	user.Hash = hash
	return m.store.PutUser(user)
}

func (m *Manager) NewSession(username string) (types.Session, error) {
	id, err := RandomToken(32)
	if err != nil {
		return types.Session{}, err
	}
	csrf, err := RandomToken(24)
	if err != nil {
		return types.Session{}, err
	}
	session := types.Session{ID: id, CSRF: csrf, Username: username, ExpiresAt: time.Now().UTC().Add(12 * time.Hour)}
	return session, m.store.PutSession(session)
}

func (m *Manager) ValidateSession(id string) (types.Session, bool) {
	session, err := m.store.GetSession(id)
	if err != nil || session.ExpiresAt.Before(time.Now().UTC()) {
		return types.Session{}, false
	}
	return session, true
}

func (m *Manager) DeleteSession(id string) error { return m.store.DeleteSession(id) }

func HashEnrollmentToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
