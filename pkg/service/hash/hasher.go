package hash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Hmac computes a hashed message authentication key.
func Hmac(plaintext, key []byte) (string, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(plaintext)
	if err != nil {
		return "", err
	}

	mac := hex.EncodeToString(h.Sum(nil))
	return mac, nil
}

// GenSalt generates random a salt.
func GenSalt(length int) (string, error) {
	nonce := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(nonce), nil
}

// Hasher interface for computing and verifying hashes.
type Hasher interface {
	Hash(plaintext, salt string) (string, error)
	Verify(plaintext, salt, hash string) error
}
