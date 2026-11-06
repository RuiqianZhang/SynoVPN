package profile

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"strconv"
	"strings"
	"synovpn/internal/config"
	"synovpn/internal/pki"
	"synovpn/internal/store"
	"testing"
	"time"
)

type xmlNode struct {
	XMLName  xml.Name
	Children []xmlNode `xml:",any"`
	Value    string    `xml:",chardata"`
}

func plistValue(n xmlNode) any {
	switch n.XMLName.Local {
	case "plist":
		return plistValue(n.Children[0])
	case "dict":
		m := map[string]any{}
		for i := 0; i < len(n.Children); i += 2 {
			m[n.Children[i].Value] = plistValue(n.Children[i+1])
		}
		return m
	case "array":
		a := []any{}
		for _, v := range n.Children {
			a = append(a, plistValue(v))
		}
		return a
	case "data":
		b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(n.Value))
		if e != nil {
			panic(e)
		}
		return b
	case "integer":
		i, _ := strconv.Atoi(n.Value)
		return i
	case "true":
		return true
	case "false":
		return false
	default:
		return n.Value
	}
}
func fixture(t *testing.T) (config.Config, store.Device, []byte, []byte, []byte) {
	t.Helper()
	c := config.Default()
	c.Domain = "vpn.example.test"
	c.Routes = []string{"192.168.1.0/24"}
	c.DNS = []string{"192.168.1.1"}
	dir := t.TempDir()
	if e := pki.Init(dir, c.Domain); e != nil {
		t.Fatal(e)
	}
	a, e := pki.OpenAuthority(dir)
	if e != nil {
		t.Fatal(e)
	}
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	key, csr, e := pki.NewKey(id)
	if e != nil {
		t.Fatal(e)
	}
	expires := time.Now().Add(time.Hour).Unix()
	issued, e := a.Issue(pki.IssueRequest{ID: id, CSR: csr, Expires: expires})
	if e != nil {
		t.Fatal(e)
	}
	server, e := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if e != nil {
		t.Fatal(e)
	}
	return c, store.Device{ID: id, Name: "我的设备 <安全>", Certificate: issued.Certificate, Serial: issued.Serial, Expires: expires}, key, server, a.CAPEM()
}
func TestAppleProfileUsesDeviceCertificateWithoutPasswordAuthentication(t *testing.T) {
	c, d, key, server, ca := fixture(t)
	for _, platform := range []string{"ios", "macos"} {
		d.Platform = platform
		f, e := Generate(c, d, key, server, ca)
		if e != nil {
			t.Fatal(e)
		}
		var root xmlNode
		if e = xml.Unmarshal(f.Data, &root); e != nil {
			t.Fatal(e)
		}
		p := plistValue(root).(map[string]any)
		contents := p["PayloadContent"].([]any)
		identity := contents[1].(map[string]any)
		vpn := contents[2].(map[string]any)["IKEv2"].(map[string]any)
		if vpn["ExtendedAuthEnabled"] != 0 || vpn["AuthenticationMethod"] != "Certificate" || vpn["PayloadCertificateUUID"] != identity["PayloadUUID"] {
			t.Fatal("not pure device certificate authentication")
		}
		for _, name := range []string{"AuthName", "AuthPassword", "SharedSecret"} {
			if _, ok := vpn[name]; ok {
				t.Fatal("password credential in VPN payload")
			}
		}
		private, cert, chain, e := pkcs12.DecodeChain(identity["PayloadContent"].([]byte), identity["Password"].(string))
		if e != nil {
			t.Fatal(e)
		}
		if cert.Subject.CommonName != pki.Identity(d.ID) || len(chain) != 1 || private.(*rsa.PrivateKey).N.Cmp(cert.PublicKey.(*rsa.PublicKey).N) != 0 {
			t.Fatal("P12 identity mismatch")
		}
		if vpn["LocalIdentifier"] != pki.DNSIdentity(d.ID) || p["PayloadDisplayName"] != "SynoVPN · "+d.Name {
			t.Fatal("profile lost escaped name or identity")
		}
	}
}
func TestWindowsAndAndroidBundlesHaveCertificatesNotLoginCredentials(t *testing.T) {
	c, d, key, server, ca := fixture(t)
	for _, platform := range []string{"windows", "android"} {
		d.Platform = platform
		f, e := Generate(c, d, key, server, ca)
		if e != nil {
			t.Fatal(e)
		}
		z, e := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
		if e != nil {
			t.Fatal(e)
		}
		files := map[string][]byte{}
		for _, entry := range z.File {
			r, e := entry.Open()
			if e != nil {
				t.Fatal(e)
			}
			files[entry.Name], e = io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
		}
		var metadata map[string]any
		if e = json.Unmarshal(files["certificate.json"], &metadata); e != nil {
			t.Fatal(e)
		}
		if metadata["username"] != nil || metadata["password"] != nil {
			t.Fatal("legacy VPN credentials exported")
		}
		_, cert, _, e := pkcs12.DecodeChain(files["SynoVPN-Device.p12"], metadata["certificate_import_password"].(string))
		if e != nil || !bytes.Equal(cert.Raw, d.Certificate) {
			t.Fatal("device P12 mismatch")
		}
		if platform == "windows" {
			if !bytes.Contains(files["install-windows.cmd"], []byte("-File \"%~dp0setup-windows.ps1\"")) {
				t.Fatal("double-click launcher missing from Windows bundle")
			}
			s := string(files["setup-windows.ps1"])
			if !strings.Contains(s, "-Verb RunAs") || !strings.Contains(s, "-EncodedCommand") || strings.Contains(s, "#Requires -RunAsAdministrator") {
				t.Fatal("Windows setup cannot request elevation")
			}
			if !strings.Contains(s, "-AuthenticationMethod MachineCertificate") || strings.Contains(s, "-AuthenticationMethod Eap") {
				t.Fatal("wrong Windows authentication")
			}
		}
	}
}
func TestExportRejectsPrivateKeyFromAnotherDevice(t *testing.T) {
	c, d, _, server, ca := fixture(t)
	other, _, e := pki.NewKey("bbbbbbbbbbbbbbbbbbbbbb")
	if e != nil {
		t.Fatal(e)
	}
	d.Platform = "ios"
	if _, e = Generate(c, d, other, server, ca); e == nil {
		t.Fatal("exported mismatched private key")
	}
	cert, _ := x509.ParseCertificate(d.Certificate)
	if cert.IsCA {
		t.Fatal("device certificate is a CA")
	}
}
