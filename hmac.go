package jwgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	// HS256 represents HMAC SHA-256 signing.
	HS256 = "HS256"
	// HS256Header is the pre-computed base64-encoded JWT header for HMAC SHA-256.
	HS256Header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	// HS256Size is the signature size for HMAC SHA-256.
	HS256Size = 32
	// HS384 represents HMAC SHA-384 signing.
	HS384 = "HS384"
	// HS384Header is the pre-computed base64-encoded JWT header for HMAC SHA-384.
	HS384Header = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"
	// HS384Size is the signature size for HMAC SHA-384.
	HS384Size = 48
	// HS512 represents HMAC SHA-512 signing.
	HS512 = "HS512"
	// HS512Header is the pre-computed base64-encoded JWT header for HMAC SHA-512.
	HS512Header = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
	// HS512Size is the signature size for HMAC SHA-512.
	HS512Size = 64
)

// HMACSHA signs and verifies JWT using HMAC SHA signing.
type HMACSHA struct {
	name   string
	header string
	size   int
	hasher hash.Hash
}

// NewHS256 creates and returns a new [HMACSHA] with HMAC SHA-256 signing.
func NewHS256(key []byte) *HMACSHA {
	return &HMACSHA{
		name:   HS256,
		header: HS256Header,
		size:   HS256Size,
		hasher: hmac.New(sha256.New, key),
	}
}

// NewHS384 creates and returns a new [HMACSHA] with HMAC SHA-384 signing.
func NewHS384(key []byte) *HMACSHA {
	return &HMACSHA{
		name:   HS384,
		header: HS384Header,
		size:   HS384Size,
		hasher: hmac.New(sha512.New384, key),
	}
}

// NewHS512 creates and returns a new [HMACSHA] with HMAC SHA-512 signing.
func NewHS512(key []byte) *HMACSHA {
	return &HMACSHA{
		name:   HS512,
		header: HS512Header,
		size:   HS512Size,
		hasher: hmac.New(sha512.New, key),
	}
}

// String returns the name of the algorithm.
func (h *HMACSHA) String() string {
	return h.name
}

// Header returns the pre-computed base64-encoded header.
func (h *HMACSHA) Header() string {
	return h.header
}

// Write writes data for signing.
func (h *HMACSHA) Write(p []byte) (int, error) {
	return h.hasher.Write(p)
}

// Sign signs the written data.
func (h *HMACSHA) Sign() ([]byte, error) {
	s := make([]byte, 0, h.size)
	s = h.hasher.Sum(s)
	return s, nil
}

// Verify verifies the written data's signature against a given signature.
func (h *HMACSHA) Verify(signature []byte) (bool, error) {
	s, _ := h.Sign()
	return hmac.Equal(s, signature), nil
}
