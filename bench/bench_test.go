package bench_test

import (
	"strings"
	"testing"

	"github.com/alvii147/jwgo"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
}

type NoOpWriter struct{}

func (w *NoOpWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkDecode(b *testing.B) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2ZXIiLCJzdWIiOiJ1c2VyIiwiYXVkIjpbImNsaWVudCJdLCJleHAiOjE3NTAwOTI1NzEsIm5iZiI6MTc0NzQxNDE3MSwiaWF0IjoxNzQ3NDE0MTcxLCJqdGkiOiIxMjMifQ.Zl2QgWz-PFUvgPmAzFPyZ0h6g199EWXEkx45buWkUOM"
	secretKeyBytes := []byte("ellogovna")
	payload := jwgo.Payload

	b.ResetTimer()
	for b.Loop() {
		r := strings.NewReader(token)
		jwgo.NewDecoder(r, secretKeyBytes).Decode(&payload)
	}
}

func BenchmarkGolangJWTParseWithClaims(b *testing.B) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2ZXIiLCJzdWIiOiJ1c2VyIiwiYXVkIjpbImNsaWVudCJdLCJleHAiOjE3NTAwOTI1NzEsIm5iZiI6MTc0NzQxNDE3MSwiaWF0IjoxNzQ3NDE0MTcxLCJqdGkiOiIxMjMifQ.Zl2QgWz-PFUvgPmAzFPyZ0h6g199EWXEkx45buWkUOM"
	secretKeyBytes := []byte("ellogovna")
	payload := Claims{}

	b.ResetTimer()
	for b.Loop() {
		jwt.ParseWithClaims(token, &payload, func(t *jwt.Token) (interface{}, error) {
			return secretKeyBytes, nil
		})
	}
}
