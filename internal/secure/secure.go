package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Key(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid key length")
		}
		return b, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	b = make([]byte, 32)
	if _, e = rand.Read(b); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return nil, e
	}
	return b, ce
}
func Seal(key []byte, plain, id string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, []byte(plain), []byte(id)), nil
}
func Open(key, data []byte, id string) (string, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	if len(data) < g.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	p, e := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte(id))
	return string(p), e
}
func CSRF(key []byte, user, cookie string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("csrf\x00" + user + "\x00" + cookie))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func Equal(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
func Atomic(path string, data []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".new-*")
	if e != nil {
		return e
	}
	n := f.Name()
	defer os.Remove(n)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(n, path)
}

// AtomicOwned sets ownership through the open descriptor before publishing the
// file. Root must never chown a path inside a directory writable by the web user.
func AtomicOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".new-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		e = f.Chown(uid, gid)
	}
	if e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
