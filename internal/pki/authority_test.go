package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func authority(t *testing.T) *Authority {
	t.Helper()
	a, e := OpenAuthority(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func request(t *testing.T, id string) ([]byte, IssueRequest) {
	t.Helper()
	key, csr, e := NewKey(id)
	if e != nil {
		t.Fatal(e)
	}
	return key, IssueRequest{ID: id, CSR: csr, Expires: time.Now().Add(time.Hour).Unix()}
}
func TestCertificateIssuanceIsBoundToDeviceKeyAndPurpose(t *testing.T) {
	a := authority(t)
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	key, req := request(t, id)
	v, e := a.Issue(req)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(v.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.ca)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: DNSIdentity(id), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("device certificate usable as server")
	}
	if cert.IsCA || cert.Subject.CommonName != Identity(id) {
		t.Fatal("unsafe certificate identity")
	}
	k, _ := x509.ParsePKCS8PrivateKey(key)
	if k.(*rsa.PrivateKey).N.Cmp(cert.PublicKey.(*rsa.PublicKey).N) != 0 {
		t.Fatal("key mismatch")
	}
	again, e := a.Issue(req)
	if e != nil || !bytes.Equal(again.Certificate, v.Certificate) {
		t.Fatal("issuance is not idempotent")
	}
	_, other := request(t, id)
	if _, e = a.Issue(other); e == nil {
		t.Fatal("another key claimed device")
	}
}
func TestCSRClaimsCannotChooseCertificateIdentity(t *testing.T) {
	a := authority(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "administrator"}, DNSNames: []string{"evil.example"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	id := "bbbbbbbbbbbbbbbbbbbbbb"
	req := IssueRequest{ID: id, CSR: csr, Expires: time.Now().Add(time.Hour).Unix()}
	issued, e := a.Issue(req)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := x509.ParseCertificate(issued.Certificate)
	if cert.Subject.CommonName != Identity(id) || len(cert.DNSNames) != 1 || cert.DNSNames[0] != DNSIdentity(id) {
		t.Fatal("CSR injected an identity")
	}
	csr[len(csr)-1] ^= 1
	req.ID = "cccccccccccccccccccccc"
	if _, e = a.Issue(req); e == nil {
		t.Fatal("invalid CSR signature accepted")
	}
}
func TestRevocationSurvivesCrashBeforeCRLPublication(t *testing.T) {
	a := authority(t)
	_, req := request(t, "aaaaaaaaaaaaaaaaaaaaaa")
	issued, e := a.Issue(req)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.RevokeIDs([]string{req.ID, "bbbbbbbbbbbbbbbbbbbbbb"}); e != nil {
		t.Fatal(e)
	}
	// Simulate a crash after the ledger write and before publishing the new CRL.
	reopened, e := OpenAuthority(a.dir)
	if e != nil {
		t.Fatal(e)
	}
	der, e := reopened.CRL()
	if e != nil {
		t.Fatal(e)
	}
	crl, e := x509.ParseRevocationList(der)
	if e != nil || crl.CheckSignatureFrom(reopened.ca) != nil {
		t.Fatal("invalid signed CRL")
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.String() != issued.Serial {
		t.Fatal("CRL lost durable revocation")
	}
	if _, e = reopened.Issue(req); e == nil {
		t.Fatal("revoked certificate reissued")
	}
	if _, e = reopened.Reconcile([]ActiveCertificate{{ID: req.ID, Certificate: issued.Certificate, Expires: req.Expires}}); e == nil {
		t.Fatal("stale snapshot resurrected certificate")
	}
	_, unissued := request(t, "bbbbbbbbbbbbbbbbbbbbbb")
	if _, e = reopened.Issue(unissued); e == nil {
		t.Fatal("late request bypassed unissued-device revocation")
	}
}
func TestMissingLedgerNeverResetsRevocations(t *testing.T) {
	a := authority(t)
	if e := os.Remove(filepath.Join(a.dir, "client-ledger.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenAuthority(a.dir); e == nil {
		t.Fatal("missing ledger silently reset")
	}
}
func TestExpiredCertificateEntersCRLWithoutWebSnapshot(t *testing.T) {
	a := authority(t)
	_, req := request(t, "aaaaaaaaaaaaaaaaaaaaaa")
	req.Expires = time.Now().Add(2 * time.Second).Unix()
	issued, e := a.Issue(req)
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Until(time.Unix(req.Expires, 0)) + 20*time.Millisecond)
	if e = a.Expire(); e != nil {
		t.Fatal(e)
	}
	der, e := a.CRL()
	if e != nil {
		t.Fatal(e)
	}
	crl, _ := x509.ParseRevocationList(der)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.String() != issued.Serial {
		t.Fatal("expired certificate absent from CRL")
	}
}
func TestClientIdentityMappingAcrossNativeClients(t *testing.T) {
	id := "AbCdEfGhIjKlMnOpQrSt_-"
	for _, identity := range []string{Identity(id), "CN=" + Identity(id), DNSIdentity(id)} {
		if DeviceID(identity) != id {
			t.Fatalf("cannot map %s", identity)
		}
	}
	for _, identity := range []string{"CN=administrator", DNSIdentity(id) + ".evil", "svpn_invalid"} {
		if DeviceID(identity) != "" {
			t.Fatal("unrelated identity matched")
		}
	}
}
