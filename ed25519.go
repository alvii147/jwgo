package jwgo

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

const (
	// EdDSA represents Ed25519 signing.
	EdDSA = "EdDSA"
	// EdDSAHeader is the pre-computed base64-encoded JWT header for Ed25519.
	EdDSAHeader = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9"
)

// ED25519 signs and verifies JWT using Ed25519 signing.
type ED25519 struct {
	data       []byte
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewEdDSA creates and returns a new [ED25519].
func NewEdDSA(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *ED25519 {
	return &ED25519{
		data:       make([]byte, 0),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// String returns the name of the algorithm.
func (e *ED25519) String() string {
	return EdDSA
}

// Header returns the pre-computed base64-encoded header.
func (e *ED25519) Header() string {
	return EdDSAHeader
}

// Grow grows the allocated size of the underlying data.
func (e *ED25519) Grow(n int) {
	newData := make([]byte, len(e.data), len(e.data)+n)
	copy(newData, e.data)
	e.data = newData
}

// Write writes data for signing.
func (e *ED25519) Write(p []byte) (int, error) {
	e.data = append(e.data, p...)
	return len(p), nil
}

// Sign signs the written data.
func (e *ED25519) Sign() ([]byte, error) {
	signature, err := e.privateKey.Sign(rand.Reader, e.data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("e.privateKey.Sign failed: %w", err)
	}

	return signature, nil
}

// Verify verifies the written data's signature against a given signature.
func (e *ED25519) Verify(signature []byte) bool {
	return ed25519.Verify(e.publicKey, e.data, signature)
}
