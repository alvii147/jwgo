package jwgo

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
		return errors.New("failed, expected three sections")
	}

	headerBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[0])))
	_, err = base64.RawURLEncoding.Decode(headerBytes, []byte(sections[0]))
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.Decode failed for header: %w", err)
	}

	header := Header{}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed for header: %w", err)
	}

	if header.Algorithm != dec.verifier.String() {
		return fmt.Errorf("failed, unsupported algorithm :%s", header.Algorithm)
	}

	signatureBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[2])))
	_, err = base64.RawURLEncoding.Decode(signatureBytes, []byte(sections[2]))
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.Decode failed for payload: %w", err)
	}

	_, err = dec.verifier.Write([]byte(sections[0]))
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for header: %w", err)
	}

	_, err = dec.verifier.Write([]byte(Separator))
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for separator: %w", err)
	}

	_, err = dec.verifier.Write([]byte(sections[1]))
	if err != nil {
		return fmt.Errorf("dec.verifier.Write failed for payload: %w", err)
	}

	if !dec.verifier.Verify(signatureBytes) {
		return errors.New("failed, invalid signature")
	}

	payloadBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[1])))
	_, err = base64.RawURLEncoding.Decode(payloadBytes, []byte(sections[1]))
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.Decode failed for payload: %w", err)
	}

	err = json.Unmarshal(payloadBytes, v)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed for payload: %w", err)
	}

	now := time.Now().UTC()
	expirationTime := v.GetExpirationTime()
	if expirationTime != nil && time.Unix(*expirationTime, 0).Before(now) {
		return fmt.Errorf("failed, token expired %d", *expirationTime)
	}

	notBefore := v.GetNotBefore()
	if notBefore != nil && time.Unix(*notBefore, 0).Before(now) {
		return fmt.Errorf("failed, token cannot be parsed before %d", *notBefore)
	}

	return nil
}
