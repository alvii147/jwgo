package bench_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alvii147/jwgo"
	"github.com/golang-jwt/jwt/v5"
)

type NoOpWriter struct{}

func (w *NoOpWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkEncode(b *testing.B) {
	now := time.Now().UTC()
	issuedAt := now.Unix()
	expirationTime := now.AddDate(0, 1, 0).Unix()
	notBefore := now.AddDate(0, 0, -1).Unix()
	key := []byte("ellogovna")
	signer := jwgo.NewHS256(key)

	b.Run("alvii147/jwgo.NewEncoder.Encode", func(b *testing.B) {
		payload := jwgo.Payload{
			Issuer:         "server",
			Subject:        "user",
			Audience:       []string{"client"},
			ExpirationTime: &expirationTime,
			NotBefore:      &notBefore,
			IssuedAt:       &issuedAt,
			JWTID:          "123",
		}
		w := new(NoOpWriter)

		b.ResetTimer()
		for b.Loop() {
			jwgo.NewEncoder(w, signer).Encode(payload)
		}
	})

	b.Run("golang-jwt/jwt.NewWithClaims.SignedString", func(b *testing.B) {
		claims := jwt.RegisteredClaims{
			Issuer:    "server",
			Subject:   "user",
			Audience:  []string{"client"},
			ExpiresAt: jwt.NewNumericDate(time.Unix(expirationTime, 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(notBefore, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(issuedAt, 0)),
			ID:        "123",
		}

		b.ResetTimer()
		for b.Loop() {
			jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		}
	})
}

func BenchmarkEncodeLargePayload(b *testing.B) {
	now := time.Now().UTC()
	issuedAt := now.Unix()
	expirationTime := now.AddDate(0, 1, 0).Unix()
	notBefore := now.AddDate(0, 0, -1).Unix()
	key := []byte("ellogovna")
	signer := jwgo.NewHS256(key)

	b.Run("alvii147/jwgo.NewEncoder.Encode", func(b *testing.B) {
		payload := jwgo.Payload{
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
		w := new(NoOpWriter)

		b.ResetTimer()
		for b.Loop() {
			jwgo.NewEncoder(w, signer).Encode(payload)
		}
	})

	b.Run("golang-jwt/jwt.NewWithClaims.SignedString", func(b *testing.B) {
		claims := jwt.RegisteredClaims{
			Issuer:  strings.Repeat("server", 20),
			Subject: strings.Repeat("user", 20),
			Audience: []string{
				strings.Repeat("client", 5),
				strings.Repeat("client", 5),
				strings.Repeat("client", 5),
				strings.Repeat("client", 5),
				strings.Repeat("client", 5),
			},
			ExpiresAt: jwt.NewNumericDate(time.Unix(expirationTime, 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(notBefore, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(issuedAt, 0)),
			ID:        strings.Repeat("123", 5),
		}

		b.ResetTimer()
		for b.Loop() {
			jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		}
	})
}

func BenchmarkDecode(b *testing.B) {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	tokenHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":"server","sub":"user","aud":["client"],"exp":%d,"nbf":%d,"iat":%d,"jti":"123"}`, expirationTime, notBefore, issuedAt)))

	key := []byte("ellogovna")
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(tokenHeader + "." + tokenPayload))
	if err != nil {
		b.Fatalf("h.Write failed %v", err)
	}

	token := tokenHeader + "." + tokenPayload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	verifier := jwgo.NewHS256(key)

	b.Run("alvii147/jwgo.NewDecoder.Decode", func(b *testing.B) {
		payload := jwgo.Payload{}
		b.ResetTimer()

		for b.Loop() {
			r := strings.NewReader(token)
			err := jwgo.NewDecoder(r, verifier).Decode(&payload)
			if err != nil {
				b.Fatalf("Decode failed %v", err)
			}
		}
	})

	b.Run("golang-jwt/jwt.ParseWithClaims", func(b *testing.B) {
		claims := jwt.RegisteredClaims{}
		b.ResetTimer()

		for b.Loop() {
			_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
				return key, nil
			})
			if err != nil {
				b.Fatalf("ParseWithClaims failed %v", err)
			}
		}
	})
}
