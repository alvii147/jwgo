[![Genocide Watch](https://hinds-banner.vercel.app/genocide-watch?variant=tatreez)](https://www.pcrf.net/)

<p align="center">
    <img alt="jwgo logo" src="docs/logo.svg" width=500 />
</p>

<p align="center">
    <strong><i>jwgo</i></strong> is a Go library efficient generation and parsing of JSON web tokens.
</p>

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/alvii147/jwgo.svg)](https://pkg.go.dev/github.com/alvii147/jwgo) [![Tests](https://img.shields.io/github/actions/workflow/status/alvii147/jwgo/github-ci.yml?branch=main&label=tests&logo=github)](https://github.com/alvii147/jwgo/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/alvii147/jwgo)](https://goreportcard.com/report/github.com/alvii147/jwgo) [![License](https://img.shields.io/github/license/alvii147/jwgo)](https://github.com/alvii147/jwgo/blob/main/LICENSE)

</div>

# Installation

Install `jwgo` using the `go get` command:

```bash
go get -u github.com/alvii147/jwgo
```

# Usage

Once installed, `jwgo` can be used to both encode and decode JWTs.

## Encoding

`jwgo.NewEncoder` can be used to encode a given payload:

```go
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alvii147/jwgo"
)

func main() {
	issuedAt := time.Now().UTC().Unix()
	expirationTime := time.Now().UTC().AddDate(0, 0, 1).Unix()
	notBefore := time.Now().UTC().AddDate(0, 0, -1).Unix()

	payload := &jwgo.Payload{
		Issuer:         "pickle",
		Subject:        "rick",
		Audience:       []string{"foo"},
		ExpirationTime: &expirationTime,
		NotBefore:      &notBefore,
		IssuedAt:       &issuedAt,
		JWTID:          "42",
	}
	key := []byte("deadbeef")
	signer := jwgo.NewHS256(key)

	var w strings.Builder
	err := jwgo.NewEncoder(&w, signer).Encode(payload)
	if err != nil {
		fmt.Fprint(os.Stderr, "encoding failed", err)
	}

	fmt.Println(w.String())
    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwaW...
}
```

## Decoding

`jwgo.NewDecoder` can be used to decode a given JWT:

```go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/alvii147/jwgo"
)

func main() {
	key := []byte("deadbeef")
	verifier := jwgo.NewHS256(key)

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwaW..."
	r := strings.NewReader(token)

	payload := jwgo.Payload{}
	err := jwgo.NewDecoder(r, verifier).Decode(&payload)
	if err != nil {
		fmt.Fprint(os.Stderr, "encoding failed", err)
	}

	fmt.Printf("%+v\n", payload)
	// {Issuer:pickle Subject:rick Audience:[foo] ExpirationTime:0x140000982f8 NotBefore:0x14000098300 IssuedAt:0x14000098308 JWTID:42}
}
```

# Signing Methods

`jwgo` supports the following signing methods:

Method Name | Method Details | Constructor Function
--- | --- | ---
`HS256` | HMAC + SHA-256 |  `NewHS256`
`HS384` | HMAC + SHA-384 | `NewHS384`
`HS512` | HMAC + SHA-512 | `NewHS512`
`RS256` | RSA-PKCS#1 v1.5 + SHA-256 | `NewRS256`
`RS384` | RSA-PKCS#1 v1.5 + SHA-384 | `NewRS384`
`RS512` | RSA-PKCS#1 v1.5 + SHA-512 | `NewRS512`
`PS256` | RSA-PSS + SHA-256 | `NewPS256`
`PS384` | RSA-PSS + SHA-384 | `NewPS384`
`PS512` | RSA-PSS + SHA-512 | `NewPS512`
`ES256` | ECDSA + SHA-256 | `NewES256`
`ES384` | ECDSA + SHA-384 | `NewES384`
`ES512` | ECDSA + SHA-512 | `NewES512`
`EdDSA` | Ed25519 | `NewEdDSA`
