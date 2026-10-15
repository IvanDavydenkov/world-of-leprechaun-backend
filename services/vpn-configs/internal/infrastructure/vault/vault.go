package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"leprechaun/vpn-configs/internal/application"
)

var ErrUnavailable = errors.New("encrypted config file unavailable")

type Blob struct {
	KeyID      string `bson:"key_id"`
	Nonce      []byte `bson:"nonce"`
	Ciphertext []byte `bson:"ciphertext"`
}

// Store persists ciphertext only. Insert is atomic and never overwrites a generation.
type Store interface {
	Insert(context.Context, string, Blob) (bool, error)
	Load(context.Context, string) (Blob, error)
}

type Vault struct {
	store Store
	aead  cipher.AEAD
	keyID string
}

var _ application.FileVault = (*Vault)(nil)

// New expects a base64-encoded random 32-byte AES key, supplied outside MongoDB.
func New(store Store, encodedKey string) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("VPN_CONFIG_ENCRYPTION_KEY must be base64 of 32 random bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(key)
	return &Vault{store: store, aead: aead, keyID: hex.EncodeToString(fingerprint[:16])}, nil
}

func identity(owner, config, generation string) (string, []byte, error) {
	if owner == "" || config == "" || generation == "" {
		return "", nil, application.ErrInvalid
	}
	aad, _ := json.Marshal([4]string{"leprechaun-vpn-file-v1", owner, config, generation})
	digest := sha256.Sum256(aad)
	return hex.EncodeToString(digest[:]), aad, nil
}

func (v *Vault) Put(ctx context.Context, owner, config, generation string, plaintext []byte) error {
	id, aad, err := identity(owner, config, generation)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 || len(plaintext) > 1024*1024 {
		return application.ErrInvalid
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	blob := Blob{KeyID: v.keyID, Nonce: nonce, Ciphertext: v.aead.Seal(nil, nonce, plaintext, aad)}
	inserted, err := v.store.Insert(ctx, id, blob)
	if err != nil {
		return ErrUnavailable
	}
	if inserted {
		return nil
	}
	existing, err := v.Get(ctx, owner, config, generation)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, plaintext) {
		return errors.New("config generation file mismatch")
	}
	return nil
}

func (v *Vault) Get(ctx context.Context, owner, config, generation string) ([]byte, error) {
	id, aad, err := identity(owner, config, generation)
	if err != nil {
		return nil, err
	}
	blob, err := v.store.Load(ctx, id)
	if errors.Is(err, application.ErrNotFound) {
		return nil, application.ErrNotFound
	}
	if err != nil || blob.KeyID != v.keyID || len(blob.Nonce) != v.aead.NonceSize() || len(blob.Ciphertext) > 1024*1024+v.aead.Overhead() {
		return nil, ErrUnavailable
	}
	plaintext, err := v.aead.Open(nil, blob.Nonce, blob.Ciphertext, aad)
	if err != nil {
		return nil, ErrUnavailable
	}
	return plaintext, nil
}
