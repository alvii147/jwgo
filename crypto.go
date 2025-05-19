package jwgo

import (
	"fmt"
	"io"
)

// Signer represents a signing algorithm.
type Signer interface {
	fmt.Stringer
	io.Writer
	Grow(n int)
	Header() string
	Sign() ([]byte, error)
}

// Verifier represents a signature verification algorithm.
type Verifier interface {
	fmt.Stringer
	io.Writer
	Grow(n int)
	Verify([]byte) (bool, error)
}
