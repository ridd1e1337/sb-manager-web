package api

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/ridd1e1337/sb-manager-web/internal/config"
	"github.com/ridd1e1337/sb-manager-web/internal/storage"
)

func TestAgentCAIssuesClientCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.Database = dir, filepath.Join(dir, "web.db")
	cfg.TLS.RequireAgentMTLS = true
	store, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, _, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.TLSConfig(); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := server.issueAgentCertificate("srv_test")
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("missing client certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "srv_test" {
		t.Fatalf("unexpected client certificate subject: %s", cert.Subject.CommonName)
	}
	if len(keyPEM) == 0 || !server.verifyAgentMTLS("srv_test", []*x509.Certificate{cert}) {
		t.Fatal("issued certificate did not verify")
	}
	if server.verifyAgentMTLS("srv_other", []*x509.Certificate{cert}) {
		t.Fatal("certificate was accepted for another server")
	}
}
