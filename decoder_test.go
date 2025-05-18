package jwgo_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alvii147/jwgo"
)

func TestDecodeHS256Success(t *testing.T) {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	tokenHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

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

func TestDecodeHS384Success(t *testing.T) {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	tokenHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS384","typ":"JWT"}`))
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

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

func TestDecodeHS512Success(t *testing.T) {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	tokenHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS512","typ":"JWT"}`))
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

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

func TestDecodeEdDSASuccess(t *testing.T) {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed %v", err)
	}

	tokenHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))
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
