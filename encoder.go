package jwgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strings"
)

// encoder is a JWT encoder.
type encoder struct {
	// w is the writer onto which the JWT will be encoded.
	w io.Writer
	// h is the hashing function.
	h hash.Hash
	// header is the pre-computed header section of the JWT.
	header []byte
	// err represents any error that occurred in the constructor.
	err error
}

// NewEncoder creates and returns a new [encoder].
func NewEncoder(w io.Writer, alg Algorithm, key []byte) *encoder {
	enc := &encoder{}
	enc.w = w

	switch alg {
	case AlgorithmHS256:
		enc.h = hmac.New(sha256.New, key)
		enc.header = []byte(HeaderHS256)
	default:
		enc.err = fmt.Errorf("failed, unsupported algorithm :%s", alg)
	}

	return enc
}

// Encode encodes a given object into a JWT.
func (enc *encoder) Encode(v any) error {
	if enc.err != nil {
		return enc.err
	}

	separatorBytes := []byte(Separator)

	payloadBytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json.Marshal failed on payload: %w", err)
	}

	payloadBytesB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(payloadBytes)))
	base64.RawURLEncoding.Encode(payloadBytesB64, payloadBytes)

	_, err = enc.h.Write(enc.header)
	if err != nil {
		return fmt.Errorf("enc.h.Write failed for header: %w", err)
	}

	_, err = enc.h.Write(separatorBytes)
	if err != nil {
		return fmt.Errorf("enc.h.Write failed for separator: %w", err)
	}

	_, err = enc.h.Write([]byte(payloadBytesB64))
	if err != nil {
		return fmt.Errorf("enc.h.Write failed for payload: %w", err)
	}

	signatureBytes := enc.h.Sum(nil)
	signatureBytesB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(signatureBytes)))
	base64.RawURLEncoding.Encode(signatureBytesB64, signatureBytes)

	var sb strings.Builder
	sb.Grow(len(enc.header) + len(separatorBytes) + len(payloadBytesB64) + len(separatorBytes) + len(signatureBytesB64))

	_, err = enc.w.Write(enc.header)
	if err != nil {
		return fmt.Errorf("enc.w.Write failed for header: %w", err)
	}

	_, err = enc.w.Write(separatorBytes)
	if err != nil {
		return fmt.Errorf("enc.w.Write failed for separator: %w", err)
	}

	_, err = enc.w.Write(payloadBytesB64)
	if err != nil {
		return fmt.Errorf("enc.w.Write failed for payload: %w", err)
	}

	_, err = enc.w.Write(separatorBytes)
	if err != nil {
		return fmt.Errorf("enc.w.Write failed for separator: %w", err)
	}

	_, err = enc.w.Write(signatureBytesB64)
	if err != nil {
		return fmt.Errorf("enc.w.Write failed for signature: %w", err)
	}

	return nil
}
