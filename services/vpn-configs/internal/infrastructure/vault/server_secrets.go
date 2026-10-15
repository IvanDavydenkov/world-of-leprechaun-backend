package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"leprechaun/vpn-configs/internal/application"
)

func (v *Vault) EncryptServerPassword(id, password string) ([]byte, error) {
	if id == "" || password == "" {
		return nil, application.ErrInvalid
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	aad, _ := json.Marshal([]string{"leprechaun-server-password-v1", id, v.keyID})
	encrypted := v.aead.Seal(nil, nonce, []byte(password), aad)
	return json.Marshal(struct {
		Version    int    `json:"version"`
		KeyID      string `json:"key_id"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}{1, v.keyID, nonce, encrypted})
}
func (v *Vault) DecryptServerPassword(id string, data []byte) (string, error) {
	var blob struct {
		Version    int    `json:"version"`
		KeyID      string `json:"key_id"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if len(data) > 16384 || json.Unmarshal(data, &blob) != nil || blob.Version != 1 || blob.KeyID != v.keyID || len(blob.Nonce) != v.aead.NonceSize() {
		return "", ErrUnavailable
	}
	aad, _ := json.Marshal([]string{"leprechaun-server-password-v1", id, v.keyID})
	plain, err := v.aead.Open(nil, blob.Nonce, blob.Ciphertext, aad)
	if err != nil {
		return "", errors.New("server credentials unavailable")
	}
	return string(plain), nil
}
