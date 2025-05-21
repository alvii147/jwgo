package jwgo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
)

const (
	// ES256 represents ECDSA SHA-256 signing.
	ES256 = "ES256"
	// ES256Header is the pre-computed base64-encoded JWT header for ES256.
	ES256Header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
	// ES256Size is key size for ES256.
	ES256Size = 32
	// ES384 represents ECDSA SHA-384 signing.
	ES384 = "ES384"
	// ES384Header is the pre-computed base64-encoded JWT header for ES384.
	ES384Header = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9"
	// ES384Size is key size for ES384.
	ES384Size = 48
	// ES512 represents ECDSA SHA-512 signing.
	ES512 = "ES512"
	// ES512Header is the pre-computed base64-encoded JWT header for ES512.
	ES512Header = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"
	// ES512Size is key size for ES512.
	ES512Size = 66
)

// ECDSA signs and verifies JWT using ECDSA signing.
type ECDSA struct {
	name       string
	header     string
	size       int
	hasher     hash.Hash
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

// NewES256 creates and returns a new [ECDSA] with ECDSA SHA-256 signing..
func NewES256(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		name:       ES256,
		header:     ES256Header,
		size:       ES256Size,
		hasher:     sha256.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewES384 creates and returns a new [ECDSA] with ECDSA SHA-384 signing..
func NewES384(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		name:       ES384,
		header:     ES384Header,
		size:       ES384Size,
		hasher:     sha512.New384(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// NewES512 creates and returns a new [ECDSA] with ECDSA SHA-512 signing..
func NewES512(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) *ECDSA {
	return &ECDSA{
		name:       ES512,
		header:     ES512Header,
		size:       ES512Size,
		hasher:     sha512.New(),
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// String returns the name of the algorithm.
func (e *ECDSA) String() string {
	return e.name
}

// Header returns the pre-computed base64-encoded header.
func (e *ECDSA) Header() string {
	return e.header
}

// Grow grows the allocated size of the underlying data.
func (e *ECDSA) Grow(n int) {
	// no data to grow
}

// Write writes data for signing.
func (e *ECDSA) Write(p []byte) (int, error) {
	return e.hasher.Write(p)
}

// Sign signs the written data.
func (e *ECDSA) Sign() ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, e.hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	signature := make([]byte, e.size*2)
	r.FillBytes(signature[:e.size])
	s.FillBytes(signature[e.size:])

	return signature, nil
}

// Verify verifies the written data's signature against a given signature.
func (e *ECDSA) Verify(signature []byte) (bool, error) {
	r := big.NewInt(0)
	s := big.NewInt(0)

	if len(signature) != e.size*2 {
		return false, nil
	}

	r.SetBytes(signature[:e.size])
	s.SetBytes(signature[e.size:])

	return ecdsa.Verify(e.publicKey, e.hasher.Sum(nil), r, s), nil
}
