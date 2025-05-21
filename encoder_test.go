package jwgo_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/alvii147/jwgo"
)

func newTestPayload(t testing.TB) (*jwgo.Payload, string) {
	t.Helper()

	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	payload := &jwgo.Payload{
		Issuer:         "server",
		Subject:        "user",
		Audience:       []string{"client"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "123",
	}
	wantPayload := fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)

	return payload, wantPayload
}

func decodeTokenSections(t testing.TB, token string) (string, []byte, string, []byte, string, []byte) {
	t.Helper()

	sections := strings.SplitN(token, ".", 3)
	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, found %d in token %s", len(sections), token)
	}

	headerB64 := sections[0]
	payloadB64 := sections[1]
	signatureB64 := sections[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString failed %v", err)
	}

	return headerB64, headerBytes, payloadB64, payloadBytes, signatureB64, signatureBytes
}

func TestEncodeHS256Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)
	key := []byte("ellogovna")
	signer := jwgo.NewHS256(key)

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := hmac.New(sha256.New, key)
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"HS256","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeHS384Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)
	key := []byte("ellogovna")
	signer := jwgo.NewHS384(key)

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := hmac.New(sha512.New384, key)
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"HS384","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeHS512Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)
	key := []byte("ellogovna")
	signer := jwgo.NewHS512(key)

	var w strings.Builder

	err := jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := hmac.New(sha512.New, key)
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	if !hmac.Equal(signatureBytes, h.Sum(nil)) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"HS512","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeRS256Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	signer := jwgo.NewRS256(publicKey, privateKey)
	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha256.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), signatureBytes)
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"RS256","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeRS384Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey
	signer := jwgo.NewRS384(publicKey, privateKey)

	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New384()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, h.Sum(nil), signatureBytes)
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"RS384","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeRS512Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey
	signer := jwgo.NewRS512(publicKey, privateKey)

	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, h.Sum(nil), signatureBytes)
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"RS512","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodePS256Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	signer := jwgo.NewPS256(publicKey, privateKey)
	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha256.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, h.Sum(nil), signatureBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"PS256","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodePS384Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey
	signer := jwgo.NewPS384(publicKey, privateKey)

	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New384()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA384, h.Sum(nil), signatureBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"PS384","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodePS512Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey
	signer := jwgo.NewPS512(publicKey, privateKey)

	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA512, h.Sum(nil), signatureBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"PS512","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeES256Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	signer := jwgo.NewES256(publicKey, privateKey)
	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha256.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r.SetBytes(signatureBytes[:32])
	s.SetBytes(signatureBytes[32:])

	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"ES256","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeES384Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	signer := jwgo.NewES384(publicKey, privateKey)
	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New384()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r.SetBytes(signatureBytes[:48])
	s.SetBytes(signatureBytes[48:])

	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"ES384","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeES512Success(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	signer := jwgo.NewES512(publicKey, privateKey)
	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	h := sha512.New()
	_, err = h.Write([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r.SetBytes(signatureBytes[:66])
	s.SetBytes(signatureBytes[66:])

	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"ES512","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}

func TestEncodeEdDSASuccess(t *testing.T) {
	payload, wantPayload := newTestPayload(t)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed %v", err)
	}
	signer := jwgo.NewEdDSA(publicKey, privateKey)

	var w strings.Builder
	err = jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		t.Fatalf("jwgo.NewEncoder failed %v", err)
	}

	token := w.String()
	headerB64, headerBytes, payloadB64, payloadBytes, _, signatureBytes := decodeTokenSections(t, token)

	if !ed25519.Verify(publicKey, []byte(headerB64+"."+payloadB64), signatureBytes) {
		t.Fatal("signature not valid")
	}

	wantHeader := `{"alg":"EdDSA","typ":"JWT"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("expected header %s, got %s", wantHeader, headerBytes)
	}

	if string(payloadBytes) != wantPayload {
		t.Fatalf("expected payload %s, got %s", wantPayload, payloadBytes)
	}
}
