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
	// PS256 represents RSA-PSS SHA-256 signing.
	PS256 = "PS256"
	// PS256Header is the pre-computed base64-encoded JWT header for PS256.
	PS256Header = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9"
	// PS384 represents RSA-PSS SHA-384 signing.
	PS384 = "PS384"
	// PS384Header is the pre-computed base64-encoded JWT header for PS384.
	PS384Header = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9"
	// PS512 represents RSA-PSS SHA-512 signing.
	PS512 = "PS512"
	// PS512Header is the pre-computed base64-encoded JWT header for PS512.
	PS512Header = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9"
)

var (
	// PSSSignOptions represents options for RSA-PSS signing.
	PSSSignOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
	// PSSVerifyOptions represents options for RSA-PSS verification.
	PSSVerifyOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
)

// RSAPSS signs and verifies JWT using RSA-PSS signing.
type RSAPSS struct {
	name       string
	header     string
	hash       crypto.Hash
	hasher     hash.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewPS256 creates and returns a new [RSAPSS] with RSA-PSS SHA-256 signing.
func NewPS256(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPSS {
	return &RSAPSS{
		name:       PS256,
		header:     PS256Header,
		hash:       crypto.SHA256,
		hasher:     sha256.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewPS384 creates and returns a new [RSAPSS] with RSA-PSS SHA-384 signing.
func NewPS384(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPSS {
	return &RSAPSS{
		name:       PS384,
		header:     PS384Header,
		hash:       crypto.SHA384,
		hasher:     sha512.New384(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewPS512 creates and returns a new [RSAPSS] with RSA-PSS SHA-512 signing.
func NewPS512(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *RSAPSS {
	return &RSAPSS{
		name:       PS512,
		header:     PS512Header,
		hash:       crypto.SHA512,
		hasher:     sha512.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// String returns the name of the algorithm.
func (rp *RSAPSS) String() string {
	return rp.name
}

// Header returns the pre-computed base64-encoded header.
func (rp *RSAPSS) Header() string {
	return rp.header
}

// Grow grows the allocated size of the underlying data.
func (rp *RSAPSS) Grow(n int) {
	// no data to grow
}

// Write writes data for signing.
func (rp *RSAPSS) Write(p []byte) (int, error) {
	return rp.hasher.Write(p)
}

// Sign signs the written data.
func (rp *RSAPSS) Sign() ([]byte, error) {
	return rsa.SignPSS(rand.Reader, rp.privateKey, rp.hash, rp.hasher.Sum(nil), PSSSignOptions)
}

// Verify verifies the written data.
func (rp *RSAPSS) Verify(signature []byte) bool {
	return rsa.VerifyPSS(rp.publicKey, rp.hash, rp.hasher.Sum(nil), signature, PSSVerifyOptions) == nil
}
