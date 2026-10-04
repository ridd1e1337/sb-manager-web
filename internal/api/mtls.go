package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/config"
)

type agentCA struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
	PEM         []byte
	Pool        *x509.CertPool
}

func loadOrCreateAgentCA(cfg config.Config) (*agentCA, error) {
	certPath := cfg.TLS.ClientCAFile
	keyPath := cfg.TLS.ClientCAKeyFile
	if certPath == "" {
		certPath = filepath.Join(cfg.DataDir, "agent-ca.pem")
	}
	if keyPath == "" {
		keyPath = filepath.Join(cfg.DataDir, "agent-ca-key.pem")
	}
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parseAgentCA(certPEM, keyPEM)
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read agent CA: %w", firstError(certErr, keyErr))
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "sb-manager-web agent CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return nil, err
	}
	if err := writePrivateFile(certPath, certPEM, 0644); err != nil {
		return nil, err
	}
	if err := writePrivateFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	return parseAgentCA(certPEM, keyPEM)
}

func parseAgentCA(certPEM, keyPEM []byte) (*agentCA, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("agent CA PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("agent CA certificate cannot be added to pool")
	}
	return &agentCA{Certificate: cert, Key: key, PEM: certPEM, Pool: pool}, nil
}

func (s *Server) ensureAgentCA() error {
	if !s.cfg.TLS.RequireAgentMTLS && s.cfg.TLS.ClientCAFile == "" && s.cfg.TLS.ClientCAKeyFile == "" {
		return nil
	}
	ca, err := loadOrCreateAgentCA(s.cfg)
	if err != nil {
		return err
	}
	s.agentCA = ca
	return nil
}

// TLSConfig is passed to net/http by cmd/sb-web. Client certificates are
// requested (rather than required at handshake time) so the token-based
// registration request can bootstrap the first certificate. Agent endpoints
// enforce the certificate when RequireAgentMTLS is enabled.
func (s *Server) TLSConfig() (*tls.Config, error) {
	if err := s.ensureAgentCA(); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.agentCA != nil {
		tlsConfig.ClientCAs = s.agentCA.Pool
		tlsConfig.ClientAuth = tls.RequestClientCert
	}
	return tlsConfig, nil
}

func (s *Server) issueAgentCertificate(serverID string) (certPEM, keyPEM []byte, err error) {
	if s.agentCA == nil {
		return nil, nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: serverID}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, s.agentCA.Certificate, &key.PublicKey, s.agentCA.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func (s *Server) verifyAgentMTLS(serverID string, certState []*x509.Certificate) bool {
	if !s.cfg.TLS.RequireAgentMTLS {
		return true
	}
	if s.agentCA == nil || len(certState) == 0 {
		return false
	}
	cert := certState[0]
	if cert.Subject.CommonName != serverID {
		return false
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: s.agentCA.Pool, Intermediates: x509.NewCertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()})
	return err == nil
}

func randomSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	return rand.Int(rand.Reader, serialLimit)
}

func writePrivateFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-ca-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func firstError(values ...error) error {
	for _, err := range values {
		if err != nil {
			return err
		}
	}
	return nil
}

func normalizePEM(value []byte) string {
	return strings.TrimSpace(string(value)) + "\n"
}
