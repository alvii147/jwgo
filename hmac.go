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
	// HS384 represents HMAC SHA-384 signing.
	HS384 = "HS384"
	// HS384Header is the pre-computed base64-encoded JWT header for HMAC SHA-384.
	HS384Header = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"
	// HS512 represents HMAC SHA-512 signing.
	HS512 = "HS512"
	// HS512Header is the pre-computed base64-encoded JWT header for HMAC SHA-512.
	HS512Header = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
)

// HMAC signs and verifies JWT using HMAC SHA signing.
type HMAC struct {
	name   string
	header string
	hasher hash.Hash
}

// NewHS256 creates and returns a new [HMAC] with HMAC SHA-256 signing.
func NewHS256(key []byte) *HMAC {
	return &HMAC{
		name:   HS256,
		header: HS256Header,
		hasher: hmac.New(sha256.New, key),
	}
}

// NewHS384 creates and returns a new [HMAC] with HMAC SHA-384 signing.
func NewHS384(key []byte) *HMAC {
	return &HMAC{
		name:   HS384,
		header: HS384Header,
		hasher: hmac.New(sha512.New384, key),
	}
}

// NewHS512 creates and returns a new [HMAC] with HMAC SHA-512 signing.
func NewHS512(key []byte) *HMAC {
	return &HMAC{
		name:   HS512,
		header: HS512Header,
		hasher: hmac.New(sha512.New, key),
	}
}

// String returns the name of the algorithm.
func (h *HMAC) String() string {
	return h.name
}

// Header returns the pre-computed base64-encoded header.
func (h *HMAC) Header() string {
	return h.header
}

// Grow grows the allocated size of the underlying data.
func (h *HMAC) Grow(n int) {
	// no data to grow
}

// Write writes data for signing.
func (h *HMAC) Write(p []byte) (int, error) {
	return h.hasher.Write(p)
}

// Sign signs the written data.
func (h *HMAC) Sign() ([]byte, error) {
	s := make([]byte, 0, h.hasher.Size())
	s = h.hasher.Sum(s)
	return s, nil
}

// Verify verifies the written data's signature against a given signature.
func (h *HMAC) Verify(signature []byte) (bool, error) {
	s := make([]byte, 0, h.hasher.Size())
	s = h.hasher.Sum(s)
	return hmac.Equal(s, signature), nil
}
