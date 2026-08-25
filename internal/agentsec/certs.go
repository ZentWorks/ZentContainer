package agentsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func EnsureControllerPKI(dir string) error {
	caCert := filepath.Join(dir, "controller-ca.crt")
	caKey := filepath.Join(dir, "controller-ca.key")
	clientCert := filepath.Join(dir, "controller-client.crt")
	clientKey := filepath.Join(dir, "controller-client.key")
	if filesExist(caCert, caKey, clientCert, clientKey) {
		return hardenPKIFiles(dir, caCert, caKey, clientCert, clientKey)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now().Add(-time.Hour)
	caTpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ZentContainer Controller CA", Organization: []string{"ZentWorks"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeCertKey(caCert, caKey, caDER, key); err != nil {
		return err
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	clientKeyObj, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	clientSerial, err := randSerial()
	if err != nil {
		return err
	}
	clientTpl := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject:      pkix.Name{CommonName: "ZentContainer Controller", Organization: []string{"ZentWorks"}},
		NotBefore:    now,
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTpl, caParsed, &clientKeyObj.PublicKey, key)
	if err != nil {
		return err
	}
	return writeCertKey(clientCert, clientKey, clientDER, clientKeyObj)
}

func EnsureAgentServerCert(dir string) error {
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if filesExist(certPath, keyPath) {
		return hardenPKIFiles(dir, certPath, keyPath)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ZentContainer Agent", Organization: []string{"ZentWorks"}},
		NotBefore:    now,
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return writeCertKey(certPath, keyPath, der, key)
}

func CertFingerprintPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("invalid certificate PEM")
	}
	h := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(h[:]), nil
}

func CertFingerprintFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return CertFingerprintPEM(b)
}

func VerifyClientCertificate(rawCerts [][]byte, caPEM []byte) error {
	if len(rawCerts) == 0 {
		return errors.New("client certificate required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid controller CA")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func hardenPKIFiles(dir string, paths ...string) error {
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	for _, path := range paths {
		if err := os.Chmod(path, 0600); err != nil {
			return err
		}
	}
	return nil
}

func filesExist(paths ...string) bool {
	for _, p := range paths {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return false
		}
	}
	return true
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writeCertKey(certPath, keyPath string, der []byte, key *rsa.PrivateKey) error {
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
}
