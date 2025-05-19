package jwgo

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

// GetTimes gets the expiration, not before, and issued at times of a [Payload].
func (p *Payload) GetTimes() (*int64, *int64, *int64) {
	return p.ExpirationTime, p.NotBefore, p.IssuedAt
}

// TimeConstrainedPayload represents payloads with timed constraints.
type TimeConstrainedPayload interface {
	GetTimes() (*int64, *int64, *int64)
}
