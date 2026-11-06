package secure

import "testing"

func TestCredentialCannotMoveBetweenDevices(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	b, e := Seal(key, "secret", "device-a")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Open(key, b, "device-b"); e == nil {
		t.Fatal("cross-device ciphertext accepted")
	}
	b[len(b)-1] ^= 1
	if _, e = Open(key, b, "device-a"); e == nil {
		t.Fatal("tampering accepted")
	}
}
