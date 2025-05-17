package bench_test

import (
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
	keyBytes := []byte("ellogovna")

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
			jwgo.NewEncoder(w, jwgo.AlgorithmHS256, keyBytes).Encode(payload)
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
			jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(keyBytes)
		}
	})
}

func BenchmarkEncodeLargePayload(b *testing.B) {
	now := time.Now().UTC()
	issuedAt := now.Unix()
	expirationTime := now.AddDate(0, 1, 0).Unix()
	notBefore := now.AddDate(0, 0, -1).Unix()
	keyBytes := []byte("ellogovna")

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
			jwgo.NewEncoder(w, jwgo.AlgorithmHS256, keyBytes).Encode(payload)
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
			jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(keyBytes)
		}
	})
}

func BenchmarkDecode(b *testing.B) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2ZXIiLCJzdWIiOiJ1c2VyIiwiYXVkIjpbImNsaWVudCJdLCJleHAiOjE3NTAwOTI1NzEsIm5iZiI6MTc0NzQxNDE3MSwiaWF0IjoxNzQ3NDE0MTcxLCJqdGkiOiIxMjMifQ.Zl2QgWz-PFUvgPmAzFPyZ0h6g199EWXEkx45buWkUOM"
	keyBytes := []byte("ellogovna")

	b.Run("alvii147/jwgo.NewDecoder.Decode", func(b *testing.B) {
		payload := jwgo.Payload{}
		b.ResetTimer()

		for b.Loop() {
			r := strings.NewReader(token)
			jwgo.NewDecoder(r, keyBytes).Decode(&payload)
		}
	})

	b.Run("golang-jwt/jwt.ParseWithClaims", func(b *testing.B) {
		claims := jwt.RegisteredClaims{}
		b.ResetTimer()

		for b.Loop() {
			jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
				return keyBytes, nil
			})
		}
	})
}
