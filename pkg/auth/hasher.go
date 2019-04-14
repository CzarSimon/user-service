package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Common errors.
var (
	ErrHashMissmatch = errors.New("Hash and data does not match")
	ErrInvalidKey    = errors.New("Invalid key")
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

// ScryptHasher implementation of Hasher using SHA-512.
type ScryptHasher struct {
	pepper []byte
	cost   int // CPU/Memory cost
	p      int // Parallelization parameter
	r      int // Blocksize parameter
	keyLen int
}

// NewHasher sets up the recommended hasher with default values.
func NewHasher(pepper string) Hasher {
	return &ScryptHasher{
		pepper: []byte(pepper),
		cost:   32768,
		p:      1,
		r:      8,
		keyLen: 64,
	}
}

// Hash hashes a plaintext password and salt.
func (h *ScryptHasher) Hash(plaintext, salt string) (string, error) {
	key, err := h.deriveKey(plaintext, salt, h.cost, h.p, h.r, h.keyLen)
	if err != nil {
		return "", err
	}

	return key.String(), nil
}

// Verify verifies that a plaintext string and forms a hash.
func (h *ScryptHasher) Verify(plaintext, salt, hash string) error {
	key, err := parseScryptKey(hash)
	if err != nil {
		return err
	}

	candidate, err := h.deriveKey(plaintext, salt, key.cost, key.p, key.r, key.keyLen)
	if err != nil {
		return err
	}

	if candidate.hash != key.hash {
		return ErrHashMissmatch
	}

	return nil
}

// deriveKey creates PBKDF2 key based plaintext and salt. Hmacs the plaintext password as part of the process.
func (h *ScryptHasher) deriveKey(plaintext, salt string, cost, p, r, kLen int) (scryptKey, error) {
	mac, err := Hmac(joinToBytes(plaintext, salt), h.pepper)
	if err != nil {
		return scryptKey{}, err
	}

	macBytes := []byte(mac)
	saltBytes := []byte(salt)
	key, err := scrypt.Key(macBytes, saltBytes, cost, r, p, kLen)
	if err != nil {
		return scryptKey{}, err
	}

	return scryptKey{
		cost:   cost,
		p:      p,
		r:      r,
		keyLen: kLen,
		hash:   hex.EncodeToString(key),
	}, nil
}

// PBKDF2Hasher implementation of Hasher using SHA-512.
type PBKDF2Hasher struct {
	pepper     []byte
	iterations int
	keyLen     int
	hashFn     func() hash.Hash
}

// Hash hashes a plaintext password and salt.
func (h *PBKDF2Hasher) Hash(plaintext, salt string) (string, error) {
	key, err := h.deriveKey(plaintext, salt, h.iterations, h.keyLen)
	if err != nil {
		return "", err
	}

	return key.String(), nil
}

// Verify verifies that a plaintext string and forms a hash.
func (h *PBKDF2Hasher) Verify(plaintext, salt, hash string) error {
	key, err := parsePbkdf2Key(hash)
	if err != nil {
		return err
	}

	candidate, err := h.deriveKey(plaintext, salt, key.iterations, key.keyLen)
	if err != nil {
		return err
	}

	if candidate.hash != key.hash {
		return ErrHashMissmatch
	}

	return nil
}

// deriveKey creates PBKDF2 key based plaintext and salt. Hmacs the plaintext password as part of the process.
func (h *PBKDF2Hasher) deriveKey(plaintext, salt string, iter, kLen int) (pbkdf2Key, error) {
	mac, err := Hmac(joinToBytes(plaintext, salt), h.pepper)
	if err != nil {
		return pbkdf2Key{}, err
	}

	macBytes := []byte(mac)
	saltBytes := []byte(salt)
	key := pbkdf2.Key(macBytes, saltBytes, iter, kLen, h.hashFn)

	return pbkdf2Key{
		iterations: iter,
		keyLen:     kLen,
		hash:       hex.EncodeToString(key),
	}, nil
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

type scryptKey struct {
	cost   int
	p      int
	r      int
	keyLen int
	hash   string
}

func (k scryptKey) String() string {
	return fmt.Sprintf("SCRYPT$%d$%d$%d$%d$%s", k.cost, k.p, k.r, k.keyLen, k.hash)
}

func parseScryptKey(str string) (scryptKey, error) {
	c := strings.Split(str, "$")
	if len(c) != 6 {
		return scryptKey{}, ErrInvalidKey
	}

	if c[0] != "SCRYPT" {
		return scryptKey{}, ErrInvalidKey
	}

	cost, err := strconv.Atoi(c[1])
	if err != nil {
		return scryptKey{}, ErrInvalidKey
	}

	p, err := strconv.Atoi(c[2])
	if err != nil {
		return scryptKey{}, ErrInvalidKey
	}

	r, err := strconv.Atoi(c[3])
	if err != nil {
		return scryptKey{}, ErrInvalidKey
	}

	keyLen, err := strconv.Atoi(c[4])
	if err != nil {
		return scryptKey{}, ErrInvalidKey
	}

	return scryptKey{
		cost:   cost,
		p:      p,
		r:      r,
		keyLen: keyLen,
		hash:   c[5],
	}, nil
}

type pbkdf2Key struct {
	iterations int
	keyLen     int
	hash       string
}

func (k pbkdf2Key) String() string {
	return fmt.Sprintf("PBKDF2$%d$%d$%s", k.iterations, k.keyLen, k.hash)
}

func parsePbkdf2Key(str string) (pbkdf2Key, error) {
	c := strings.Split(str, "$")
	if len(c) != 4 {
		return pbkdf2Key{}, ErrInvalidKey
	}

	if c[0] != "PBKDF2" {
		return pbkdf2Key{}, ErrInvalidKey
	}

	iter, err := strconv.Atoi(c[1])
	if err != nil {
		return pbkdf2Key{}, ErrInvalidKey
	}

	keyLen, err := strconv.Atoi(c[2])
	if err != nil {
		return pbkdf2Key{}, ErrInvalidKey
	}

	return pbkdf2Key{
		iterations: iter,
		keyLen:     keyLen,
		hash:       c[3],
	}, nil
}

func joinToBytes(args ...string) []byte {
	joined := strings.Join(args, "-")
	return []byte(joined)
}
