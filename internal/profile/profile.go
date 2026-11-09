package profile

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"sort"
	"synovpn/internal/config"
	"synovpn/internal/pki"
	"synovpn/internal/secure"
	"synovpn/internal/store"
)

type File struct {
	Name, Type string
	Data       []byte
}

func uuid() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func payload(kind, name string) map[string]any {
	return map[string]any{"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": "local.synovpn." + uuid(), "PayloadUUID": uuid(), "PayloadDisplayName": name}
}
func parseCA(raw []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("invalid CA")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return nil, e
	}
	if !c.IsCA {
		return nil, fmt.Errorf("not a CA")
	}
	return c, nil
}
func Generate(c config.Config, d store.Device, keyDER, serverCA, clientCA []byte) (File, error) {
	if !pki.IDPattern.MatchString(d.ID) {
		return File{}, fmt.Errorf("invalid device")
	}
	cert, e := x509.ParseCertificate(d.Certificate)
	if e != nil {
		return File{}, e
	}
	issuer, e := parseCA(clientCA)
	if e != nil {
		return File{}, e
	}
	serverRoot, e := parseCA(serverCA)
	if e != nil {
		return File{}, e
	}
	key, e := x509.ParsePKCS8PrivateKey(keyDER)
	if e != nil {
		return File{}, e
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return File{}, fmt.Errorf("unsupported private key")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || rsaKey.N.Cmp(pub.N) != 0 || cert.Subject.CommonName != pki.Identity(d.ID) || cert.CheckSignatureFrom(issuer) != nil || cert.SerialNumber.String() != d.Serial || cert.NotAfter.Unix() != d.Expires {
		return File{}, fmt.Errorf("device key/certificate mismatch")
	}
	importPassword := secure.Random(24)
	// Use legacy PKCS#12 wrapping for Apple and Android compatibility. Protect the whole authenticated
	// download as sensitive material; this wrapper is not a VPN account password.
	encoder := pkcs12.Modern
	if d.Platform == "ios" || d.Platform == "macos" || d.Platform == "android" {
		encoder = pkcs12.LegacyDES
	}
	pfx, e := encoder.Encode(key, cert, []*x509.Certificate{issuer}, importPassword)
	if e != nil {
		return File{}, e
	}
	if d.Platform == "ios" || d.Platform == "macos" {
		root := payload("com.apple.security.root", "SynoVPN Server CA")
		root["PayloadContent"] = serverRoot.Raw
		identity := payload("com.apple.security.pkcs12", "SynoVPN · "+d.Name+" 设备证书")
		identity["PayloadContent"] = pfx
		identity["Password"] = importPassword
		vpn := payload("com.apple.vpn.managed", "SynoVPN · "+d.Name)
		vpn["UserDefinedName"] = "SynoVPN · " + d.Name
		vpn["VPNType"] = "IKEv2"
		vpn["IPv4"] = map[string]any{"OverridePrimary": 0}
		vpn["IKEv2"] = map[string]any{"RemoteAddress": c.Domain, "RemoteIdentifier": c.Domain, "LocalIdentifier": pki.DNSIdentity(d.ID), "AuthenticationMethod": "Certificate", "ExtendedAuthEnabled": 0, "CertificateType": "RSA", "PayloadCertificateUUID": identity["PayloadUUID"], "ServerCertificateCommonName": c.Domain, "ServerCertificateIssuerCommonName": serverRoot.Subject.CommonName, "DeadPeerDetectionRate": "Medium", "DisableMOBIKE": 0, "EnablePFS": false, "IKESecurityAssociationParameters": map[string]any{"EncryptionAlgorithm": "AES-256", "IntegrityAlgorithm": "SHA2-256", "DiffieHellmanGroup": 14, "LifeTimeInMinutes": 1440}, "ChildSecurityAssociationParameters": map[string]any{"EncryptionAlgorithm": "AES-256", "IntegrityAlgorithm": "SHA2-256", "DiffieHellmanGroup": 14, "LifeTimeInMinutes": 60}}
		profile := payload("Configuration", "SynoVPN · "+d.Name)
		profile["PayloadDescription"] = "设备专属证书连接，无需 VPN 账号和密码。配置含私钥，请勿转发。"
		profile["PayloadContent"] = []any{root, identity, vpn}
		var b bytes.Buffer
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">`)
		plist(&b, profile)
		b.WriteString("</plist>")
		return File{"SynoVPN-" + d.ID + ".mobileconfig", "application/x-apple-aspen-config", b.Bytes()}, nil
	}
	metadata, _ := json.MarshalIndent(map[string]any{"name": "SynoVPN-" + d.ID, "server": c.Domain, "device_id": d.ID, "local_identifier": pki.DNSIdentity(d.ID), "certificate_serial": d.Serial, "certificate_import_password": importPassword, "routes": c.TrafficRoutes(), "dns": c.DNS}, "", "  ")
	instructions := "设备：" + d.Name + "\r\n使用设备证书连接，无需 VPN 用户名或密码。配置含私钥，请勿分享，安装后删除下载副本。\r\n\r\nWindows：解压，在管理员 PowerShell 中运行 setup-windows.ps1，核对两个 CA 的指纹并确认安装。脚本创建机器证书认证的 IKEv2 配置；之后直接从系统 VPN 连接。相同 NAS 签发的其他有效设备证书已存在时，脚本会停止，需先解绑并手动移除旧证书，避免选错身份。\r\n\r\nAndroid：先从安全设置导入 SynoVPN-Device.p12，导入用途选择 VPN/应用；导入密码见 certificate.json 的 certificate_import_password。这仅用于首次证书导入，并非 VPN 登录密码。另安装 SynoVPN-Server-CA.cer。添加 IKEv2/IPSec RSA，选择导入的客户端证书及服务器 CA；服务器/远程标识填 " + c.Domain + "，本地标识填 " + pki.DNSIdentity(d.ID) + "。不同版本和厂商支持不同，若无该选项不能保证免装客户端。\r\n\r\n解绑会撤销该证书、阻止重连并断开现有连接。证书可被复制，不能视为硬件锁定。按管理员配置分流内网和指定公网 IPv4，其余互联网流量保持原路径，不接管 IPv6。管理员修改当前用户的访问规则后，Apple 和 Android 请断开后重新连接；Windows 请重新下载此配置包，解压后运行 update-windows-routes.ps1（不需要重新安装证书）。\r\n"
	files := map[string][]byte{"certificate.json": metadata, "SynoVPN-Device.p12": pfx, "SynoVPN-Server-CA.cer": serverRoot.Raw, "SynoVPN-Client-CA.cer": issuer.Raw, "使用说明.txt": []byte(instructions)}
	if d.Platform == "windows" {
		files["setup-windows.ps1"] = []byte(windowsScript)
		files["update-windows-routes.ps1"] = []byte(windowsRouteScript)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, e := z.Create(n)
		if e != nil {
			return File{}, e
		}
		if _, e = f.Write(files[n]); e != nil {
			return File{}, e
		}
	}
	if e = z.Close(); e != nil {
		return File{}, e
	}
	return File{"SynoVPN-" + d.ID + ".zip", "application/zip", b.Bytes()}, nil
}

//go:embed update-windows-routes.ps1
var windowsRouteScript string

//go:embed setup-windows.ps1
var windowsScript string

func plist(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		b.WriteString("<dict>")
		ks := []string{}
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			b.WriteString("<key>")
			xml.EscapeText(b, []byte(k))
			b.WriteString("</key>")
			plist(b, x[k])
		}
		b.WriteString("</dict>")
	case []any:
		b.WriteString("<array>")
		for _, e := range x {
			plist(b, e)
		}
		b.WriteString("</array>")
	case []byte:
		b.WriteString("<data>" + base64.StdEncoding.EncodeToString(x) + "</data>")
	case string:
		b.WriteString("<string>")
		xml.EscapeText(b, []byte(x))
		b.WriteString("</string>")
	case int:
		fmt.Fprintf(b, "<integer>%d</integer>", x)
	case bool:
		if x {
			b.WriteString("<true/>")
		} else {
			b.WriteString("<false/>")
		}
	default:
		panic("unsupported plist value")
	}
}
