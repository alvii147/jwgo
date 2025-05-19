package jwgo

import "errors"

var (
	// ErrInvalidToken indicates token parsing errors.
	ErrInvalidToken = errors.New("invalid token")
	// ErrUnsupportedAlgorithm indicates the algorithm on the token's header is unsupported.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	// ErrInvalidSignature indicates a verification error in the token's signature.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrExpired indicates that the token is expired.
	ErrExpired = errors.New("expired")
	// ErrNotYetEffectiveToken indicates that the token is not yet effective.
	ErrNotYetEffectiveToken = errors.New("not yet effective")
	// ErrInvalidIssuedAt indicates that the token has an invalid issued at time.
	ErrInvalidIssuedAt = errors.New("invalid issued at")
)
