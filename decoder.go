package jwgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

// decoder is a JWT decoder.
type decoder struct {
	// r is the reader from which the JWT will be decoded.
	r io.Reader
	// key is the signing key.
	key []byte
}

// NewDecoder creates and returns a new [decoder].
func NewDecoder(r io.Reader, key []byte) *decoder {
	dec := &decoder{}
	dec.r = r
	dec.key = key

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

	var h hash.Hash
	var eq func([]byte, []byte) bool

	switch header.Algorithm {
	case AlgorithmHS256:
		h = hmac.New(sha256.New, dec.key)
		eq = hmac.Equal
	default:
		return fmt.Errorf("failed, unsupported algorithm :%s", header.Algorithm)
	}

	signatureBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(sections[2])))
	_, err = base64.RawURLEncoding.Decode(signatureBytes, []byte(sections[2]))
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.Decode failed for payload: %w", err)
	}

	_, err = h.Write([]byte(sections[0]))
	if err != nil {
		return fmt.Errorf("h.Write failed for header: %w", err)
	}

	_, err = h.Write([]byte(Separator))
	if err != nil {
		return fmt.Errorf("h.Write failed for separator: %w", err)
	}

	_, err = h.Write([]byte(sections[1]))
	if err != nil {
		return fmt.Errorf("h.Write failed for payload: %w", err)
	}

	if !eq(signatureBytes, h.Sum(nil)) {
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
