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

type NoOpWriter struct{}

func (w *NoOpWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
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

func BenchmarkEncodeHS256(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS256(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeHS256LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS256(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeHS384(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS384(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeHS384LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS384(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeHS512(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS512(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeHS512LargePayload(b *testing.B) {
	key := []byte("ellogovna")
	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewHS512(key)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeRS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeRS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeRS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeRS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeRS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeRS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewRS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodePS256(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodePS256LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodePS384(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodePS384LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodePS512(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodePS512LargePayload(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewPS512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeES256(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeES256LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES256(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeES384(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeES384LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES384(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeES512(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeES512LargePayload(b *testing.B) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey failed %v", err)
	}
	publicKey := &privateKey.PublicKey

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewES512(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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

func BenchmarkEncodeEdDSA(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	payload, _ := newTestPayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewEdDSA(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
		}
	}
}

func BenchmarkEncodeEdDSALargePayload(b *testing.B) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey %v", err)
	}

	payload, _ := newTestLargePayload(b)
	w := new(NoOpWriter)

	b.ResetTimer()
	for b.Loop() {
		signer := jwgo.NewEdDSA(publicKey, privateKey)
		err := jwgo.NewEncoder(w, signer).Encode(payload)
		if err != nil {
			b.Fatalf("Encode failed %v", err)
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
