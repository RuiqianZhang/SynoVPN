package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"synovpn/internal/secure"
	"time"
)

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func Init(dir, domain string) error {
	if _, e := os.Stat(filepath.Join(dir, "server.key")); e == nil {
		return errors.New("PKI already exists; refusing to overwrite keys")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	caKey, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		return e
	}
	serverKey, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "SynoVPN " + domain + " Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	for n, v := range map[string][]byte{"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "ca.key": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}), "server.key": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})} {
		if e = secure.Atomic(filepath.Join(dir, n), v, 0600); e != nil {
			return e
		}
	}
	// Server and client CA keys are stored only in the root-owned PKI directory.
	return nil
}
func DER(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid PEM")
	}
	return p.Bytes, nil
}
