package vault

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestServerPasswordEncryptionBinding(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	v, _ := New(nil, key)
	first, err := v.EncryptServerPassword("server-a", "password")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := v.EncryptServerPassword("server-a", "password")
	if bytes.Equal(first, second) {
		t.Fatal("nonce reused")
	}
	if _, err = v.DecryptServerPassword("server-b", first); err == nil {
		t.Fatal("wrong server decrypted")
	}
	other, _ := New(nil, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if _, err = other.DecryptServerPassword("server-a", first); err == nil {
		t.Fatal("wrong key decrypted")
	}
	first[len(first)/2] ^= 1
	if _, err = v.DecryptServerPassword("server-a", first); err == nil {
		t.Fatal("tampered blob decrypted")
	}
}
