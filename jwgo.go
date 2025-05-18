package jwgo

import (
	"fmt"
	"io"
)

const (
	// Separator is the character separating different sections on the JWT.
	Separator string = "."
)

// Header represents the cryptographic operations applied to the JWT.
type Header struct {
	// Algorithm is the signing algorithm used to sign the JWT.
	Algorithm string `json:"alg"`
	// Type represents the media type, which is always "JWT" in this case.
	Type string `json:"typ"`
}

// Payload represents registered claims conveyed by the JWT.
type Payload struct {
	// Issuer identifies the principal that issued the JWT.
	Issuer string `json:"iss,omitempty"`
	// Subject identifies the principal that is the subject of the JWT.
	Subject string `json:"sub,omitempty"`
	// Audience identifies the recipients that the JWT is intended for.
	Audience []string `json:"aud,omitempty"`
	// ExpirationTime identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
	ExpirationTime *int64 `json:"exp,omitempty"`
	// NotBefore identifies the time before which the JWT MUST NOT be accepted for processing.
	NotBefore *int64 `json:"nbf,omitempty"`
	// IssuedAt identifies the time at which the JWT was issued.
	IssuedAt *int64 `json:"iat,omitempty"`
	// JWTID provides a unique identifier for the JWT.
	JWTID string `json:"jti,omitempty"`
}

// GetExpirationTime gets the expiration time of a [Payload].
func (p *Payload) GetExpirationTime() *int64 {
	return p.ExpirationTime
}

// GetNotBefore gets the not before time of a [Payload].
func (p *Payload) GetNotBefore() *int64 {
	return p.NotBefore
}

// TimeConstrainedPayload represents payloads with expiration and not before time constraints.
type TimeConstrainedPayload interface {
	GetExpirationTime() *int64
	GetNotBefore() *int64
}

// Signer represents a signing algorithm.
type Signer interface {
	fmt.Stringer
	io.Writer
	Header() string
	Sign() []byte
}

// Verifier represents a signature verification algorithm.
type Verifier interface {
	fmt.Stringer
	io.Writer
	Verify([]byte) bool
}
