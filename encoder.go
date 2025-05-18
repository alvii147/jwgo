package jwgo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// encoder is a JWT encoder.
type encoder struct {
	// w is the writer onto which the JWT will be encoded.
	w io.Writer
	// signer is used to sign the JWT.
	signer Signer
}

// NewEncoder creates and returns a new [encoder].
func NewEncoder(w io.Writer, signer Signer) *encoder {
	enc := &encoder{}
	enc.w = w
	enc.signer = signer

	return enc
}

// Encode encodes a given object into a JWT.
func (enc *encoder) Encode(v any) error {
	payloadBytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json.Marshal failed on payload: %w", err)
	}

	payloadBytesB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(payloadBytes)))
	base64.RawURLEncoding.Encode(payloadBytesB64, payloadBytes)
	headerBytesB64 := []byte(enc.signer.Header())

	_, err = enc.signer.Write(headerBytesB64)
	if err != nil {
		return fmt.Errorf("enc.signer.Write failed for header: %w", err)
	}

	separatorBytes := []byte(Separator)
	_, err = enc.signer.Write(separatorBytes)
	if err != nil {
		return fmt.Errorf("enc.signer.Write failed for separator: %w", err)
	}

	_, err = enc.signer.Write([]byte(payloadBytesB64))
	if err != nil {
		return fmt.Errorf("enc.signer.Write failed for payload: %w", err)
	}

	signatureBytes := enc.signer.Sign()
	signatureBytesB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(signatureBytes)))
	base64.RawURLEncoding.Encode(signatureBytesB64, signatureBytes)

	_, err = enc.w.Write(headerBytesB64)
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
