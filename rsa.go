package jwgo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	// RS256 represents RSA-PKCS#1 v1.5 SHA-256 signing.
	RS256 = "RS256"
	// RS256Header is the pre-computed base64-encoded JWT header for RS256.
	RS256Header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	// RS384 represents RSA-PKCS#1 v1.5 SHA-384 signing.
	RS384 = "RS384"
	// RS384Header is the pre-computed base64-encoded JWT header for RS384.
	RS384Header = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"
	// RS512 represents RSA-PKCS#1 v1.5 SHA-512 signing.
	RS512 = "RS512"
	// RS512Header is the pre-computed base64-encoded JWT header for RS512.
	RS512Header = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9"
)

// RSAPKCS1v15 signs and verifies JWT using RSA-PKCS#1 v1.5 signing.
type RSAPKCS1v15 struct {
	name       string
	header     string
	hash       crypto.Hash
	hasher     hash.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRS256 creates and returns a new [RSAPKCS1v15] with RSA-PKCS#1 v1.5 SHA-256 signing.
func NewRS256(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPKCS1v15 {
	return &RSAPKCS1v15{
		name:       RS256,
		header:     RS256Header,
		hash:       crypto.SHA256,
		hasher:     sha256.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewRS384 creates and returns a new [RSAPKCS1v15] with RSA-PKCS#1 v1.5 SHA-384 signing.
func NewRS384(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPKCS1v15 {
	return &RSAPKCS1v15{
		name:       RS384,
		header:     RS384Header,
		hash:       crypto.SHA384,
		hasher:     sha512.New384(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewRS512 creates and returns a new [RSAPKCS1v15] with RSA-PKCS#1 v1.5 SHA-512 signing.
func NewRS512(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPKCS1v15 {
	return &RSAPKCS1v15{
		name:       RS512,
		header:     RS512Header,
		hash:       crypto.SHA512,
		hasher:     sha512.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// String returns the name of the algorithm.
func (r *RSAPKCS1v15) String() string {
	return r.name
}

// Header returns the pre-computed base64-encoded header.
func (r *RSAPKCS1v15) Header() string {
	return r.header
}

// Grow grows the allocated size of the underlying data.
func (r *RSAPKCS1v15) Grow(n int) {
	// no data to grow
}

// Write writes data for signing.
func (r *RSAPKCS1v15) Write(p []byte) (int, error) {
	return r.hasher.Write(p)
}

// Sign signs the written data.
func (r *RSAPKCS1v15) Sign() ([]byte, error) {
	s := make([]byte, 0, r.hasher.Size())
	s = r.hasher.Sum(s)
	return rsa.SignPKCS1v15(rand.Reader, r.privateKey, r.hash, s)
}

// Sign signs the written data.
func (r *RSAPKCS1v15) Verify(signature []byte) (bool, error) {
	s := make([]byte, 0, r.hasher.Size())
	s = r.hasher.Sum(s)
	return rsa.VerifyPKCS1v15(r.publicKey, r.hash, s, signature) == nil, nil
}
