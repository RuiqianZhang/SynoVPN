package profile

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestPublicRoutesAcrossPlatformExports(t *testing.T) {
	c, d, key, server, ca := fixture(t)
	c.PublicRoutes = []string{"8.8.8.8/32"}
	for _, platform := range []string{"macos", "ios", "android", "windows"} {
		t.Run(platform, func(t *testing.T) {
			d.Platform = platform
			f, err := Generate(c, d, key, server, ca)
			if err != nil {
				t.Fatal(err)
			}
			if platform == "ios" || platform == "macos" {
				var doc xmlNode
				if xml.Unmarshal(f.Data, &doc) != nil {
					t.Fatal("invalid profile")
				}
				payloads := plistValue(doc).(map[string]any)["PayloadContent"].([]any)
				vpn := payloads[2].(map[string]any)
				if vpn["IPv4"].(map[string]any)["OverridePrimary"] != 0 {
					t.Fatal("default route captured")
				}
				return
			}
			z, err := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
			if err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{}
			for _, entry := range z.File {
				r, e := entry.Open()
				if e != nil {
					t.Fatal(e)
				}
				files[entry.Name], err = io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			var meta struct {
				Routes []string `json:"routes"`
			}
			if json.Unmarshal(files["certificate.json"], &meta) != nil || !slices.Equal(meta.Routes, c.TrafficRoutes()) {
				t.Fatal("export missed combined routes")
			}
			if platform == "windows" {
				script := string(files["update-windows-routes.ps1"])
				for _, needed := range []string{"Remove-VpnConnectionRoute", "Add-VpnConnectionRoute", "Disconnected", "-SplitTunneling $true"} {
					if !strings.Contains(script, needed) {
						t.Fatalf("route updater missing %s", needed)
					}
				}
				if strings.Contains(script, "Import-PfxCertificate") {
					t.Fatal("updater reimports private key")
				}
			}
		})
	}
}
