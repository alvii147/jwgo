package jwgo_test

import (
	"strings"
	"testing"

	"github.com/alvii147/jwgo"
)

func TestDecodeHS256Success(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzZXJ2ZXIiLCJzdWIiOiJ1c2VyIiwiYXVkIjpbImNsaWVudCJdLCJleHAiOjE2ODMyNjY4MjgsIm5iZiI6MTY3Nzk5NjQyOCwiaWF0IjoxNjgwNjc0ODI4LCJqdGkiOiIxMjMifQ.MdawpM-gu6l4vUhLHg6AY9Oc09EYjauynr0orqf7hPg"
	key := []byte("ellogovna")
	verifier := jwgo.NewHS256(key)
	payload := jwgo.Payload{}

	r := strings.NewReader(token)
	jwgo.NewDecoder(r, verifier).Decode(&payload)

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

	if *payload.ExpirationTime != 1683266828 {
		t.Fatalf("expected exp %d, got %d", 1683266828, *payload.ExpirationTime)
	}

	if payload.NotBefore == nil {
		t.Fatal("expected nbf")
	}

	if *payload.NotBefore != 1677996428 {
		t.Fatalf("expected nbf %d, got %d", 1677996428, *payload.NotBefore)
	}

	if payload.IssuedAt == nil {
		t.Fatal("expected iat")
	}

	if *payload.IssuedAt != 1680674828 {
		t.Fatalf("expected iat %d, got %d", 1680674828, *payload.IssuedAt)
	}

	if payload.JWTID != "123" {
		t.Fatalf("expected jti %s, got %s", "123", payload.JWTID)
	}
}
