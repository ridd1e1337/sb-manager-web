package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"os"
	"time"
)

// Private operation payloads never enter the task JSON or audit log. The key
// lives beside the DB and must be included in protected controller backups.
func (s *Store) openSecretKey(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var count int
		if err = s.db.QueryRow(`SELECT COUNT(*) FROM task_secrets`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("task secret key is missing; restore the original database key")
		}
		data = make([]byte, 32)
		if _, err = rand.Read(data); err != nil {
			return err
		}
		file, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if openErr != nil {
			return openErr
		}
		_, err = file.Write(data)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(data) != 32 {
		return errors.New("task secret key must be a private 32-byte regular file")
	}
	block, err := aes.NewCipher(data)
	if err != nil {
		return err
	}
	s.secretKey = append([]byte(nil), data...)
	s.secretAEAD, err = cipher.NewGCM(block)
	return err
}

func (s *Store) sealSecret(taskID, name string, plain []byte) ([]byte, error) {
	nonce := make([]byte, s.secretAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.secretAEAD.Seal(nonce, nonce, plain, []byte(taskID+"\x00"+name)), nil
}
func (s *Store) openSecret(taskID, name string, sealed []byte) ([]byte, error) {
	n := s.secretAEAD.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("invalid private task payload")
	}
	return s.secretAEAD.Open(nil, sealed[:n], sealed[n:], []byte(taskID+"\x00"+name))
}
func (s *Store) PutTaskSecret(taskID, name string, plain []byte, expires time.Time) error {
	sealed, err := s.sealSecret(taskID, name, plain)
	if err != nil {
		return err
	}
	until := int64(0)
	if !expires.IsZero() {
		until = expires.Unix()
	}
	_, err = s.db.Exec(`INSERT INTO task_secrets(task_id,name,expires_at,data) VALUES(?,?,?,?) ON CONFLICT(task_id,name) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data`, taskID, name, until, sealed)
	return err
}
func (s *Store) TaskSecret(taskID, name string, consume bool) ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var sealed []byte
	var until int64
	if err = tx.QueryRow(`SELECT expires_at,data FROM task_secrets WHERE task_id=? AND name=?`, taskID, name).Scan(&until, &sealed); err != nil {
		return nil, err
	}
	if until != 0 && until <= time.Now().Unix() {
		if _, err = tx.Exec(`DELETE FROM task_secrets WHERE task_id=? AND name=?`, taskID, name); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, sql.ErrNoRows
	}
	plain, err := s.openSecret(taskID, name, sealed)
	if err != nil {
		return nil, err
	}
	if consume {
		if _, err = tx.Exec(`DELETE FROM task_secrets WHERE task_id=? AND name=?`, taskID, name); err != nil {
			return nil, err
		}
	}
	return plain, tx.Commit()
}
