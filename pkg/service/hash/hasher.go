package hash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Common errors.
var (
	ErrHashMissmatch = errors.New("Hash and data does not match")
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

// Sha512Hasher implementation of Hasher using SHA-512.
type Sha512Hasher struct {
	pepper []byte
}

// Hash hashes a plaintext password and salt.
func (h *Sha512Hasher) Hash(plaintext, salt string) (string, error) {
	mac, err := Hmac(joinToBytes(plaintext, salt), h.pepper)
	if err != nil {
		return "", err
	}

	hash := sha512.Sum512([]byte(mac))
	return fmt.Sprintf("%x", hash), nil
}

// Verify verifies that a plaintext string and forms a hash.
func (h *Sha512Hasher) Verify(plaintext, salt, hash string) error {
	computedHash, err := h.Hash(plaintext, salt)
	if err != nil {
		return err
	}

	if computedHash != hash {
		return ErrHashMissmatch
	}

	return nil
}

func joinToBytes(args ...string) []byte {
	joined := strings.Join(args, "-")
	return []byte(joined)
}
