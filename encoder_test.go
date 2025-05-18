package jwgo_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/alvii147/jwgo"
)

func TestEncodeHS256Success(t *testing.T) {
	issuedAt := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC).Unix()
	expirationTime := time.Date(2023, 5, 5, 6, 7, 8, 0, time.UTC).Unix()
	notBefore := time.Date(2023, 3, 5, 6, 7, 8, 0, time.UTC).Unix()
	key := []byte("ellogovna")
	signer := jwgo.NewHS256(key)

	payload := jwgo.Payload{
		Issuer:         "server",
		Subject:        "user",
		Audience:       []string{"client"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "123",
	}

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(&payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	sections := strings.SplitN(token, ".", 3)
	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, found %d in token %s", len(sections), token)
	}

	headerB64 := sections[0]
	payloadB64 := sections[1]
	signatureB64 := sections[2]

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(sections[0]))
	h.Write([]byte("."))
	h.Write([]byte(sections[1]))

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantHeader := `{"alg":"HS256","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantPayload := `{"iss":"server","sub":"user","aud":["client"],"exp":1683266828,"nbf":1677996428,"iat":1680674828,"jti":"123"}`
	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeHS384Success(t *testing.T) {
	issuedAt := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC).Unix()
	expirationTime := time.Date(2023, 5, 5, 6, 7, 8, 0, time.UTC).Unix()
	notBefore := time.Date(2023, 3, 5, 6, 7, 8, 0, time.UTC).Unix()
	key := []byte("ellogovna")
	signer := jwgo.NewHS384(key)

	payload := jwgo.Payload{
		Issuer:         "server",
		Subject:        "user",
		Audience:       []string{"client"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "123",
	}

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(&payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	sections := strings.SplitN(token, ".", 3)
	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, found %d in token %s", len(sections), token)
	}

	headerB64 := sections[0]
	payloadB64 := sections[1]
	signatureB64 := sections[2]

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	h := hmac.New(sha512.New384, key)
	h.Write([]byte(sections[0]))
	h.Write([]byte("."))
	h.Write([]byte(sections[1]))

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantHeader := `{"alg":"HS384","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantPayload := `{"iss":"server","sub":"user","aud":["client"],"exp":1683266828,"nbf":1677996428,"iat":1680674828,"jti":"123"}`
	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeHS512Success(t *testing.T) {
	issuedAt := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC).Unix()
	expirationTime := time.Date(2023, 5, 5, 6, 7, 8, 0, time.UTC).Unix()
	notBefore := time.Date(2023, 3, 5, 6, 7, 8, 0, time.UTC).Unix()
	key := []byte("ellogovna")
	signer := jwgo.NewHS512(key)

	payload := jwgo.Payload{
		Issuer:         "server",
		Subject:        "user",
		Audience:       []string{"client"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "123",
	}

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(&payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	sections := strings.SplitN(token, ".", 3)
	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, found %d in token %s", len(sections), token)
	}

	headerB64 := sections[0]
	payloadB64 := sections[1]
	signatureB64 := sections[2]

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	h := hmac.New(sha512.New, key)
	h.Write([]byte(sections[0]))
	h.Write([]byte("."))
	h.Write([]byte(sections[1]))

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantHeader := `{"alg":"HS512","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantPayload := `{"iss":"server","sub":"user","aud":["client"],"exp":1683266828,"nbf":1677996428,"iat":1680674828,"jti":"123"}`
	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeEdDSASuccess(t *testing.T) {
	issuedAt := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC).Unix()
	expirationTime := time.Date(2023, 5, 5, 6, 7, 8, 0, time.UTC).Unix()
	notBefore := time.Date(2023, 3, 5, 6, 7, 8, 0, time.UTC).Unix()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey %v", err)
	}

	signer := jwgo.NewEdDSA(publicKey, privateKey)

	payload := jwgo.Payload{
		Issuer:         "server",
		Subject:        "user",
		Audience:       []string{"client"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "123",
	}

	var w strings.Builder

	err = jwgo.NewEncoder(&w, signer).Encode(&payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	sections := strings.SplitN(token, ".", 3)
	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, found %d in token %s", len(sections), token)
	}

	headerB64 := sections[0]
	payloadB64 := sections[1]
	signatureB64 := sections[2]

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	if !ed25519.Verify(publicKey, []byte(sections[0]+"."+sections[1]), signatureBytes) {
		t.Fatal("signature not valid")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantHeader := `{"alg":"EdDSA","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	wantPayload := `{"iss":"server","sub":"user","aud":["client"],"exp":1683266828,"nbf":1677996428,"iat":1680674828,"jti":"123"}`
	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}
