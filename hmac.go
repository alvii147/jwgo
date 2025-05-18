package jwgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

const (
	// HS256Name represents HMAC SHA-256 signing.
	HS256Name = "HS256"
	// HS256Header is the pre-computed base64-encoded JWT header for HMAC SHA-256.
	HS256Header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	// HS256SignatureLen is the checksum length for HMAC SHA-256.
	HS256SignatureLen = 32
)

// HS256 signs and verifies JWT using HMAC SHA-256 signing.
type HS256 struct {
	h hash.Hash
}

// NewHS256 creates and returns a new [HS256].
func NewHS256(key []byte) *HS256 {
	return &HS256{
		h: hmac.New(sha256.New, key),
	}
}

// String returns the name of the algorithm.
func (hs256 *HS256) String() string {
	return HS256Name
}

// Header returns the pre-computed base64-encoded header.
func (hs256 *HS256) Header() string {
	return HS256Header
}

// Write writes data for signing.
func (hs256 *HS256) Write(p []byte) (int, error) {
	return hs256.h.Write(p)
}

// Sign signs the written data.
func (hs256 *HS256) Sign() []byte {
	s := make([]byte, 0, HS256SignatureLen)
	s = hs256.h.Sum(s)
	return s
}

// Verify verifies the written data's signature against a given signature.
func (hs256 *HS256) Verify(signature []byte) bool {
	s := hs256.Sign()
	return hmac.Equal(s, signature)
}
