package secretcrypt

import "encoding"

// Secret represents an encrypted secret
type Secret interface {
	Decrypt() (string, error)
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}
