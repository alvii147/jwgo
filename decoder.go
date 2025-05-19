package jwgo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// decoder is a JWT decoder.
type decoder struct {
	// r is the reader from which the JWT will be decoded.
	r io.Reader
	// verifier is used to verify the JWT.
	verifier Verifier
}

// NewDecoder creates and returns a new [decoder].
func NewDecoder(r io.Reader, verifier Verifier) *decoder {
	dec := &decoder{}
	dec.r = r
	dec.verifier = verifier

	return dec
}

// Decode decodes a JWT into a given object.
func (dec *decoder) Decode(v TimeConstrainedPayload) error {
	token, err := io.ReadAll(dec.r)
	if err != nil {
		return fmt.Errorf("io.ReadAll failed: %w", err)
	}

	sections := strings.SplitN(string(token), Separator, 3)
	if len(sections) != 3 {
		return ErrInvalidToken
	}

	headerBytesB64 := []byte(sections[0])
	payloadBytesB64 := []byte(sections[1])
	signatureBytesB64 := []byte(sections[2])
	separatorBytes := []byte(Separator)

	headerBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(headerBytesB64)))
	_, err = base64.RawURLEncoding.Decode(headerBytes, headerBytesB64)
	if err != nil {
		return ErrInvalidToken
	}

	header := Header{}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return ErrInvalidToken
	}

	if header.Algorithm != dec.verifier.String() {
		return ErrUnsupportedAlgorithm
	}

	signatureBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(signatureBytesB64)))
	_, err = base64.RawURLEncoding.Decode(signatureBytes, signatureBytesB64)
	if err != nil {
		return ErrInvalidToken
	}

	dec.verifier.Grow(len(headerBytesB64) + len(separatorBytes) + len(payloadBytesB64))

	_, err = dec.verifier.Write(headerBytesB64)
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for header: %w", err)
	}

	_, err = dec.verifier.Write(separatorBytes)
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for separator: %w", err)
	}

	_, err = dec.verifier.Write(payloadBytesB64)
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for payload: %w", err)
	}

	verified, err := dec.verifier.Verify(signatureBytes)
	if err != nil {
		return fmt.Errorf("dec.verifier.Verify failed: %w", err)
	}

	if !verified {
		return ErrInvalidSignature
	}

	payloadBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(payloadBytesB64)))
	_, err = base64.RawURLEncoding.Decode(payloadBytes, payloadBytesB64)
	if err != nil {
		return ErrInvalidToken
	}

	err = json.Unmarshal(payloadBytes, v)
	if err != nil {
		return ErrInvalidToken
	}

	expirationTime, notBefore, issuedAt := v.GetTimes()
	now := time.Now().UTC().Unix()

	if expirationTime != nil && *expirationTime < now {
		return ErrExpired
	}

	if notBefore != nil && *notBefore > now {
		return ErrNotYetEffectiveToken
	}

	if issuedAt != nil && *issuedAt > now {
		return ErrInvalidIssuedAt
	}

	return nil
}
