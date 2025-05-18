package jwgo

// Algorithm represents a signing algorithm.
type Algorithm string

const (
	// AlgorithmHS256 represents HMAC SHA-256 signing.
	AlgorithmHS256 Algorithm = "HS256"
	// HeaderHS256 is the pre-computed base64-encoded JWT header for HMAC SHA-256.
	HeaderHS256 string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	// CheckSumLenHS256 is the checksum length for HMAC SHA-256.
	CheckSumLenHS256 int = 32
	// Separator is the character separating different sections on the JWT.
	Separator string = "."
)

// Header represents the cryptographic operations applied to the JWT.
type Header struct {
	// Algorithm is the signing algorithm used to sign the JWT.
	Algorithm Algorithm `json:"alg"`
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
