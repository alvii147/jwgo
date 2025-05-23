package main_test

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
	"github.com/golang-jwt/jwt/v5"
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

func newTestLargePayload(t testing.TB) (*jwgo.Payload, string) {
	t.Helper()

	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	payload := &jwgo.Payload{
		Issuer:  strings.Repeat("server", 20),
		Subject: strings.Repeat("user", 20),
		Audience: []string{
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
		},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          strings.Repeat("123", 5),
	}
	wantPayload := fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)

	return payload, wantPayload
}

func newTestClaims(t testing.TB) (*jwt.RegisteredClaims, string) {
	t.Helper()

	claims := &jwt.RegisteredClaims{
		Issuer:    "server",
		Subject:   "user",
		Audience:  []string{"client"},
		ExpiresAt: &jwt.NumericDate{Time: time.Now().UTC().AddDate(0, 0, 1)},
		NotBefore: &jwt.NumericDate{Time: time.Now().UTC().AddDate(0, 0, -1)},
		IssuedAt:  &jwt.NumericDate{Time: time.Now().UTC()},
		ID:        "123",
	}

	wantPayload := fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, claims.ExpiresAt.Unix(), claims.NotBefore.Unix(), claims.IssuedAt.Unix())

	return claims, wantPayload
}

func newTestLargeClaims(t testing.TB) (*jwt.RegisteredClaims, string) {
	t.Helper()

	claims := &jwt.RegisteredClaims{
		Issuer:  strings.Repeat("server", 20),
		Subject: strings.Repeat("user", 20),
		Audience: []string{
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
			strings.Repeat("client", 5),
		},
		ExpiresAt: &jwt.NumericDate{Time: time.Now().UTC().AddDate(0, 0, 1)},
		NotBefore: &jwt.NumericDate{Time: time.Now().UTC().AddDate(0, 0, -1)},
		IssuedAt:  &jwt.NumericDate{Time: time.Now().UTC()},
		ID:        strings.Repeat("123", 5),
	}

	wantPayload := fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, claims.ExpiresAt.Unix(), claims.NotBefore.Unix(), claims.IssuedAt.Unix())

	return claims, wantPayload
}

func newTestToken(t testing.TB, algorithm string) (string, string, int64, int64, int64) {
	t.Helper()

	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"%s","typ":"JWT"}`, algorithm)))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

	return header, payload, issuedAt, expirationTime, notBefore
}

// -----
// HS256
// -----

func BenchmarkJWGOEncodeHS256(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS256(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS256(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeHS256LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS256(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS256LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeHS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS256")
	key := []byte("ellogovna")

	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewHS256(key)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsHS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS256")
	key := []byte("ellogovna")

	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// HS384
// -----

func BenchmarkJWGOEncodeHS384(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS384(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS384(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeHS384LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS384(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS384LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeHS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS384")
	key := []byte("ellogovna")

	h := hmac.New(sha512.New384, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewHS384(key)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsHS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS384")
	key := []byte("ellogovna")

	h := hmac.New(sha512.New384, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// HS512
// -----

func BenchmarkJWGOEncodeHS512(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS512(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS512(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeHS512LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewHS512(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringHS512LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(key)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeHS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS512")
	key := []byte("ellogovna")

	h := hmac.New(sha512.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewHS512(key)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsHS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "HS512")
	key := []byte("ellogovna")

	h := hmac.New(sha512.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// RS256
// -----

func BenchmarkJWGOEncodeRS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeRS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeRS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewRS256(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsRS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// RS384
// -----

func BenchmarkJWGOEncodeRS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeRS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeRS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewRS384(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsRS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// RS512
// -----

func BenchmarkJWGOEncodeRS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeRS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewRS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringRS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeRS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewRS512(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsRS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "RS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil))
	if err != nil {
		b.Fatalf("rsa.SignPKCS1v15 %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// PS256
// -----

func BenchmarkJWGOEncodePS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodePS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodePS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewPS256(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsPS256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS256")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// PS384
// -----

func BenchmarkJWGOEncodePS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodePS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodePS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewPS384(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsPS384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS384")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// PS512
// -----

func BenchmarkJWGOEncodePS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodePS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewPS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringPS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodPS512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodePS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewPS512(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsPS512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "PS512")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		b.Fatalf("rsa.SignPSS %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// ES256
// -----

func BenchmarkJWGOEncodeES256(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES256(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeES256LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES256LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeES256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES256")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 64)
	r.FillBytes(signatureBytes[:32])
	s.FillBytes(signatureBytes[32:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewES256(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsES256(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES256")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha256.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 64)
	r.FillBytes(signatureBytes[:32])
	s.FillBytes(signatureBytes[32:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// ES384
// -----

func BenchmarkJWGOEncodeES384(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES384(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeES384LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES384LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES384, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeES384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES384")

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 96)
	r.FillBytes(signatureBytes[:48])
	s.FillBytes(signatureBytes[48:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewES384(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsES384(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES384")

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New384()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 96)
	r.FillBytes(signatureBytes[:48])
	s.FillBytes(signatureBytes[48:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// ES512
// -----

func BenchmarkJWGOEncodeES512(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES512(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeES512LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewES512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringES512LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodES512, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeES512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES512")

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 132)
	r.FillBytes(signatureBytes[:66])
	s.FillBytes(signatureBytes[66:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewES512(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsES512(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "ES512")

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	h := sha512.New()
	_, err = h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		b.Fatalf("ecdsa.Sign %v", err)
	}

	signatureBytes := make([]byte, 132)
	r.FillBytes(signatureBytes[:66])
	s.FillBytes(signatureBytes[66:])

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}

// -----
// EdDSA
// -----

func BenchmarkJWGOEncodeEdDSA(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	payload, _ := newTestPayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewEdDSA(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringEdDSA(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	claims, _ := newTestClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkJWGOEncodeEdDSALargePayload(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	payload, _ := newTestLargePayload(b)

	b.ResetTimer()
	for b.Loop() {
		w := new(strings.Builder)
		signer := jwgo.NewEdDSA(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTSignedStringEdDSALargePayload(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	claims, _ := newTestLargeClaims(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
		if err != nil {
			b.Fatalf("SignedString failed %v", err)
		}
	}
}

func BenchmarkDecodeEdDSA(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "EdDSA")

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey failed %v", err)
	}

	signatureBytes, err := privateKey.Sign(rand.Reader, []byte(tokenHeader+"."+tokenPayload), crypto.Hash(0))
	if err != nil {
		b.Fatalf("privateKey.Sign failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	payload := jwgo.Payload{}
	b.ResetTimer()

	for b.Loop() {
		r := strings.NewReader(token)
		verifier := jwgo.NewEdDSA(publicKey, privateKey)
		err := jwgo.NewDecoder(r, verifier).Decode(&payload)
		if err != nil {
			b.Fatalf("Decode failed %v", err)
		}
	}
}

func BenchmarkGolangJWTParseWithClaimsEdDSA(b *testing.B) {
	tokenHeader, tokenPayload, _, _, _ := newTestToken(b, "EdDSA")

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey failed %v", err)
	}

	signatureBytes, err := privateKey.Sign(rand.Reader, []byte(tokenHeader+"."+tokenPayload), crypto.Hash(0))
	if err != nil {
		b.Fatalf("privateKey.Sign failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
	claims := &jwt.RegisteredClaims{}
	b.ResetTimer()

	for b.Loop() {
		_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("ParseWithClaims failed %v", err)
		}
	}
}
