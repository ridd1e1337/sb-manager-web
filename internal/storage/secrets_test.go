package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func TestEncryptedTaskPayloadsBackupAndConsumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secret := []byte(`{"url":"https://source.example/sub/private-credential"}`)
	if err = store.PutTaskSecret("one", "args", secret, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err = store.PutTaskSecret("one", "result", secret, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err = store.db.QueryRow(`SELECT data FROM task_secrets WHERE task_id='one' AND name='args'`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private-credential")) {
		t.Fatal("private argument stored as plaintext")
	}
	if _, err = store.openSecret("different-task", "args", sealed); err == nil {
		t.Fatal("ciphertext was not bound to task identity")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = store.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	plain, err := restored.TaskSecret("one", "args", false)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("backup lost encrypted payload: %v", err)
	}
	plain, err = store.TaskSecret("one", "result", true)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("failed to retrieve payload: %v", err)
	}
	if _, err = store.TaskSecret("one", "result", true); err == nil {
		t.Fatal("one-time result can be read again")
	}
	if err = store.PutTaskSecret("two", "result", secret, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.TaskSecret("two", "result", true); err == nil {
		t.Fatal("expired private result returned")
	}
	info, err := os.Stat(backup + ".secrets.key")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup key is not protected")
	}
}

func TestNonIdempotentOperationIsNotRepeatedOnControllerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.PutTask(types.Task{ID: "expiry", ServerID: "local", Action: "node.expiry.days", Status: types.TaskRunning, ManualRecovery: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task, err := store.GetTask("expiry")
	if err != nil || task.Status != types.TaskFailed {
		t.Fatal("node extension would be applied twice after restart")
	}
}
