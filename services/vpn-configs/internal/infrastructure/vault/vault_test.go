package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

type memoryBlobs map[string]Blob

func (m memoryBlobs) Insert(_ context.Context, id string, b Blob) (bool, error) {
	if _, ok := m[id]; ok {
		return false, nil
	}
	m[id] = b
	return true, nil
}
func (m memoryBlobs) Load(_ context.Context, id string) (Blob, error) { return m[id], nil }

func TestEncryptedPersistenceAndContextBinding(t *testing.T) {
	ctx := context.Background()
	store := memoryBlobs{}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	v, err := New(store, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("[Interface]\nPrivateKey = secret\n")
	if err = v.Put(ctx, "alice", "phone", "generation1", plaintext); err != nil {
		t.Fatal(err)
	}
	id, _, _ := identity("alice", "phone", "generation1")
	blob := store[id]
	if bytes.Contains(blob.Ciphertext, []byte("PrivateKey")) || bytes.Equal(blob.Ciphertext, plaintext) {
		t.Fatal("plaintext persisted")
	}
	// A new process with the same key decrypts without contacting the VPN host.
	restarted, _ := New(store, key)
	downloaded, err := restarted.Get(ctx, "alice", "phone", "generation1")
	if err != nil || !bytes.Equal(downloaded, plaintext) {
		t.Fatal("download mismatch", err)
	}
	if err = v.Put(ctx, "alice", "phone", "generation1", plaintext); err != nil {
		t.Fatal(err)
	}
	if err = v.Put(ctx, "alice", "phone", "generation1", []byte("different")); err == nil {
		t.Fatal("immutable generation overwritten")
	}
	otherID, _, _ := identity("bob", "phone", "generation1")
	store[otherID] = blob
	if _, err = v.Get(ctx, "bob", "phone", "generation1"); err == nil {
		t.Fatal("ciphertext accepted for another owner")
	}
	blob.Ciphertext[0] ^= 1
	store[id] = blob
	if _, err = v.Get(ctx, "alice", "phone", "generation1"); err == nil {
		t.Fatal("tampering accepted")
	}
}

func TestInvalidAndChangedKeys(t *testing.T) {
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := New(memoryBlobs{}, key); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	ctx := context.Background()
	store := memoryBlobs{}
	a, _ := New(store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	b, _ := New(store, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	if err := a.Put(ctx, "alice", "id", "gen", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "alice", "id", "gen"); err == nil {
		t.Fatal("wrong key accepted")
	}
}
