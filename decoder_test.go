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
	"strings"
	"testing"
	"time"

	"github.com/alvii147/jwgo"
)

func newTestToken(t testing.TB, algorithm string) (string, string, int64, int64, int64) {
	t.Helper()

	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"%s","typ":"JWT"}`, algorithm)))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

	return header, payload, issuedAt, expirationTime, notBefore
}

func validatePayload(t testing.TB, payload *jwgo.Payload, issuedAt int64, expirationTime int64, notBefore int64) {
	t.Helper()

	if payload.Issuer != "server" {
		t.Fatalf("expected iss %s, got %s", "server", payload.Issuer)
	}

	if payload.Subject != "user" {
		t.Fatalf("expected sub %s, got %s", "user", payload.Subject)
	}

	if len(payload.Audience) != 1 || payload.Audience[0] != "client" {
		t.Fatalf("expected aud %v, got %v", []string{"client"}, payload.Audience)
	}

	if payload.ExpirationTime == nil {
		t.Fatal("expected exp")
	}

	if *payload.ExpirationTime != expirationTime {
		t.Fatalf("expected exp %d, got %d", expirationTime, *payload.ExpirationTime)
	}

	if payload.NotBefore == nil {
		t.Fatal("expected nbf")
	}

	if *payload.NotBefore != notBefore {
		t.Fatalf("expected nbf %d, got %d", notBefore, *payload.NotBefore)
	}

	if payload.IssuedAt == nil {
		t.Fatal("expected iat")
	}

	if *payload.IssuedAt != issuedAt {
		t.Fatalf("expected iat %d, got %d", issuedAt, *payload.IssuedAt)
	}

	if payload.JWTID != "123" {
		t.Fatalf("expected jti %s, got %s", "123", payload.JWTID)
	}
}

func TestDecodeHS256Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "HS256")

	key := []byte("ellogovna")
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	verifier := jwgo.NewHS256(key)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeHS384Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "HS384")

	key := []byte("ellogovna")
	h := hmac.New(sha512.New384, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	verifier := jwgo.NewHS384(key)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeHS512Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "HS512")

	key := []byte("ellogovna")
	h := hmac.New(sha512.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	verifier := jwgo.NewHS512(key)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeRS256Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "RS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewRS256(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeRS384Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "RS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil))
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewRS384(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeRS512Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "RS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil))
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewRS512(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodePS256Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "PS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewPS256(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodePS384Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "PS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewPS384(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodePS512Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "PS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewPS512(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeES256Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "ES256")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		t.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 64)
	r.FillBytes(signatureBytes[:32])
	s.FillBytes(signatureBytes[32:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewES256(publicKey, privateKey)
	payload := jwgo.Payload{}

	err = jwgo.NewDecoder(strings.NewReader(token), verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeES384Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "ES384")

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		t.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 96)
	r.FillBytes(signatureBytes[:48])
	s.FillBytes(signatureBytes[48:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewES384(publicKey, privateKey)
	payload := jwgo.Payload{}

	err = jwgo.NewDecoder(strings.NewReader(token), verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeES512Success(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "ES512")

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		t.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		t.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 132)
	r.FillBytes(signatureBytes[:66])
	s.FillBytes(signatureBytes[66:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewES512(publicKey, privateKey)
	payload := jwgo.Payload{}

	err = jwgo.NewDecoder(strings.NewReader(token), verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}

func TestDecodeEdDSASuccess(t *testing.T) {
	tokenHeader, tokenPayload, issuedAt, expirationTime, notBefore := newTestToken(t, "EdDSA")

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed %v", err)
	}

	signatureBytes, err := privateKey.Sign(rand.Reader, []byte(tokenHeader+"."+tokenPayload), crypto.Hash(0))
	if err != nil {
		t.Fatalf("privateKey.Sign failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	verifier := jwgo.NewEdDSA(publicKey, privateKey)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	err = jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		t.Fatalf("Decode failed %v", err)
	}

	validatePayload(t, &payload, issuedAt, expirationTime, notBefore)
}
