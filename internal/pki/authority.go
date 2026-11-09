package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"synovpn/internal/secure"
	"time"
)

var IDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

func Identity(id string) string { return "svpn_" + id }
func DNSIdentity(id string) string {
	return "device-" + hex.EncodeToString([]byte(id)) + ".synovpn.invalid"
}
func DeviceID(identity string) string {
	s := strings.TrimPrefix(identity, "CN=")
	if strings.HasPrefix(s, "svpn_") {
		s = strings.TrimPrefix(s, "svpn_")
		if IDPattern.MatchString(s) {
			return s
		}
	}
	s = strings.ToLower(identity)
	if strings.HasPrefix(s, "device-") && strings.HasSuffix(s, ".synovpn.invalid") {
		b, e := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(s, "device-"), ".synovpn.invalid"))
		if e == nil && IDPattern.Match(b) {
			return string(b)
		}
	}
	return ""
}

type Issued struct {
	Certificate []byte `json:"certificate"`
	Serial      string `json:"serial"`
	Expires     int64  `json:"expires"`
}
type IssueRequest struct {
	ID      string `json:"id"`
	CSR     []byte `json:"csr"`
	Expires int64  `json:"expires"`
}
type ActiveCertificate struct {
	ID          string
	Certificate []byte
	Expires     int64
}
type record struct {
	Issued
	Revoked int64 `json:"revoked,omitempty"`
}
type ledger struct {
	Number  int64             `json:"crl_number"`
	Devices map[string]record `json:"devices"`
}
type Authority struct {
	mu    sync.Mutex
	dir   string
	ca    *x509.Certificate
	key   *rsa.PrivateKey
	state ledger
}

func NewKey(id string) ([]byte, []byte, error) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	csr, e := CSR(id, der)
	return der, csr, e
}
func CSR(id string, keyDER []byte) ([]byte, error) {
	if !IDPattern.MatchString(id) {
		return nil, errors.New("invalid device id")
	}
	key, e := x509.ParsePKCS8PrivateKey(keyDER)
	if e != nil {
		return nil, e
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: Identity(id)}}, key)
}

// OpenAuthority keeps a separate client CA and durable issuance/revocation
// ledger in the root-owned PKI directory. Existing server certificates survive.
func OpenAuthority(dir string) (*Authority, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	caPath, keyPath := filepath.Join(dir, "client-ca.pem"), filepath.Join(dir, "client-ca.key")
	_, ce := os.Stat(caPath)
	_, ke := os.Stat(keyPath)
	created := false
	if os.IsNotExist(ce) && os.IsNotExist(ke) {
		if _, e := os.Stat(filepath.Join(dir, "client-ledger.json")); !os.IsNotExist(e) {
			return nil, errors.New("client CA missing but ledger exists")
		}
		key, e := rsa.GenerateKey(rand.Reader, 3072)
		if e != nil {
			return nil, e
		}
		now := time.Now()
		tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "SynoVPN Device CA " + secure.Random(8)}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
		der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if e != nil {
			return nil, e
		}
		if e = secure.Atomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
			return nil, e
		}
		if e = secure.Atomic(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			return nil, e
		}
		created = true
	}
	der, e := DER(caPath)
	if e != nil {
		return nil, e
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	kd, e := DER(keyPath)
	if e != nil {
		return nil, e
	}
	key, e := x509.ParsePKCS1PrivateKey(kd)
	if e != nil {
		return nil, e
	}
	pub, ok := ca.PublicKey.(*rsa.PublicKey)
	if !ok || !ca.IsCA || !bytes.Equal(x509.MarshalPKCS1PublicKey(&key.PublicKey), x509.MarshalPKCS1PublicKey(pub)) {
		return nil, errors.New("client CA key mismatch")
	}
	a := &Authority{dir: dir, ca: ca, key: key, state: ledger{Devices: map[string]record{}}}
	raw, e := os.ReadFile(filepath.Join(dir, "client-ledger.json"))
	if e == nil {
		if e = json.Unmarshal(raw, &a.state); e != nil {
			return nil, e
		}
		if a.state.Devices == nil || a.state.Number < 0 {
			return nil, errors.New("invalid client ledger")
		}
		for id, r := range a.state.Devices {
			if len(r.Certificate) == 0 && r.Revoked != 0 && IDPattern.MatchString(id) {
				continue
			}
			cert, e := x509.ParseCertificate(r.Certificate)
			if e != nil || !IDPattern.MatchString(id) || cert.Subject.CommonName != Identity(id) || cert.SerialNumber.String() != r.Serial || cert.NotAfter.Unix() != r.Expires || cert.CheckSignatureFrom(ca) != nil {
				return nil, errors.New("client ledger certificate mismatch")
			}
		}
	} else if !created {
		return nil, errors.New("client ledger missing or unreadable; restore the complete PKI backup")
	}
	if _, e = a.crlLocked(false); e != nil {
		return nil, e
	}
	return a, nil
}
func (a *Authority) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.ca.Raw})
}
func (a *Authority) Issue(req IssueRequest) (Issued, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var none Issued
	if !IDPattern.MatchString(req.ID) || req.Expires <= time.Now().Unix() || req.Expires > time.Now().Add(366*24*time.Hour).Unix() || len(req.CSR) > 8192 {
		return none, errors.New("invalid certificate request")
	}
	csr, e := x509.ParseCertificateRequest(req.CSR)
	if e != nil {
		return none, e
	}
	if e = csr.CheckSignature(); e != nil {
		return none, e
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 || pub.N.BitLen() > 4096 {
		return none, errors.New("RSA 2048-4096 required")
	}
	if r, ok := a.state.Devices[req.ID]; ok {
		if r.Revoked != 0 {
			return none, errors.New("device permanently revoked")
		}
		cert, e := x509.ParseCertificate(r.Certificate)
		if e != nil {
			return none, e
		}
		if r.Revoked != 0 || r.Expires <= time.Now().Unix() {
			return none, errors.New("certificate permanently revoked or expired")
		}
		if r.Expires != req.Expires || !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
			return none, errors.New("device already belongs to another key")
		}
		return r.Issued, nil
	}
	if time.Unix(req.Expires, 0).After(a.ca.NotAfter) {
		return none, errors.New("client CA expires before device")
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: Identity(req.ID)}, DNSNames: []string{DNSIdentity(req.ID)}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Unix(req.Expires, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 8, 2, 2}}}
	der, e := x509.CreateCertificate(rand.Reader, cert, a.ca, csr.PublicKey, a.key)
	if e != nil {
		return none, e
	}
	issued := Issued{der, cert.SerialNumber.String(), req.Expires}
	a.state.Devices[req.ID] = record{Issued: issued}
	if e = a.save(); e != nil {
		delete(a.state.Devices, req.ID)
		return none, e
	}
	return issued, nil
}
func (a *Authority) Reconcile(active []ActiveCertificate) ([]byte, error) {
	return a.ReconcilePending(active, nil)
}

// Pending IDs retain issuance ledger entries without granting a usable session.
// This permits retry after a lost issuance response or failed Web DB commit.
func (a *Authority) ReconcilePending(active []ActiveCertificate, pending []string) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	want := map[string]bool{}
	for _, id := range pending {
		if !IDPattern.MatchString(id) {
			return nil, errors.New("invalid pending identity")
		}
		want[id] = true
	}
	for _, d := range active {
		r, ok := a.state.Devices[d.ID]
		if !ok || r.Revoked != 0 || r.Expires != d.Expires || !bytes.Equal(r.Certificate, d.Certificate) {
			return nil, errors.New("unissued or revoked device certificate")
		}
		want[d.ID] = true
	}
	changed := false
	now := time.Now().Unix()
	for id, r := range a.state.Devices {
		if (!want[id] || r.Expires <= now) && r.Revoked == 0 {
			r.Revoked = now
			a.state.Devices[id] = r
			changed = true
		}
	}
	// Persist revocation before publishing CRL. A restart may never resurrect it.
	if changed {
		if e := a.save(); e != nil {
			return nil, e
		}
	}
	return a.crlLocked(changed)
}
func (a *Authority) CRL() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.crlLocked(false)
}
func (a *Authority) Expire() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for id, r := range a.state.Devices {
		if r.Revoked == 0 && r.Expires <= time.Now().Unix() {
			r.Revoked = time.Now().Unix()
			a.state.Devices[id] = r
			changed = true
		}
	}
	if changed {
		return a.save()
	}
	return nil
}
func (a *Authority) RevokeIDs(ids []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		if !IDPattern.MatchString(id) {
			return errors.New("invalid device id")
		}
	}
	changed := false
	for _, id := range ids {
		r := a.state.Devices[id]
		if r.Revoked == 0 {
			r.Revoked = time.Now().Unix()
			a.state.Devices[id] = r
			changed = true
		}
	}
	if changed {
		return a.save()
	}
	return nil
}
func (a *Authority) save() error {
	b, e := json.Marshal(a.state)
	if e != nil {
		return e
	}
	return secure.Atomic(filepath.Join(a.dir, "client-ledger.json"), b, 0600)
}
func (a *Authority) crlLocked(force bool) ([]byte, error) {
	path := filepath.Join(a.dir, "client-crl.der")
	if !force {
		if b, e := os.ReadFile(path); e == nil {
			if crl, e := x509.ParseRevocationList(b); e == nil && crl.CheckSignatureFrom(a.ca) == nil && crl.Number != nil && crl.Number.Int64() == a.state.Number && a.matchesCRL(crl) && crl.NextUpdate.After(time.Now().Add(6*time.Hour)) {
				return b, nil
			}
		}
	}
	a.state.Number++
	if e := a.save(); e != nil {
		return nil, e
	}
	entries := []x509.RevocationListEntry{}
	for _, r := range a.state.Devices {
		if r.Revoked != 0 && len(r.Certificate) > 0 {
			n, ok := new(big.Int).SetString(r.Serial, 10)
			if !ok {
				return nil, errors.New("invalid revoked serial")
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: time.Unix(r.Revoked, 0), ReasonCode: 5})
		}
	}
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(a.state.Number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(24 * time.Hour), RevokedCertificateEntries: entries}, a.ca, a.key)
	if e != nil {
		return nil, e
	}
	if e = secure.Atomic(path, der, 0600); e != nil {
		return nil, e
	}
	return der, nil
}

func (a *Authority) matchesCRL(crl *x509.RevocationList) bool {
	want := map[string]int64{}
	for _, r := range a.state.Devices {
		if r.Revoked != 0 && len(r.Certificate) > 0 {
			want[r.Serial] = r.Revoked
		}
	}
	if len(want) != len(crl.RevokedCertificateEntries) {
		return false
	}
	for _, r := range crl.RevokedCertificateEntries {
		v, ok := want[r.SerialNumber.String()]
		if !ok || v != r.RevocationTime.Unix() {
			return false
		}
	}
	return true
}
