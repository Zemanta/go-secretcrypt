package secretcrypt

import (
	"fmt"
	"strings"

	"github.com/Zemanta/go-secretcrypt/internal"
)

// Secret represents an encrypted secret
type Secret struct {
	crypter       internal.Crypter
	ciphertext    internal.Ciphertext
	decryptParams internal.DecryptParams
}

// Decrypt decrypts the secret
func (s Secret) Decrypt() (string, error) {
	return s.crypter.Decrypt(s.ciphertext, s.decryptParams)
}

// MarshalText marshalls the secret into its textual representation
func (s Secret) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf(
		"%s:%s:%s",
		s.crypter.Name(),
		internal.UnparseDecryptParams(s.decryptParams),
		s.ciphertext,
	)), nil
}

// UnmarshalText loads the secret from its textual representation
func (s *Secret) UnmarshalText(text []byte) error {
	tokens := strings.SplitN(string(text), ":", 3)
	if len(tokens) < 3 {
		return fmt.Errorf("Malformed secret '%s'", text)
	}

	var exists bool
	s.crypter, exists = internal.CryptersMap[tokens[0]]
	if !exists {
		return fmt.Errorf("Invalid crypter name in secret %s", text)
	}

	var err error
	s.decryptParams, err = internal.ParseDecryptParams(tokens[1])
	if err != nil {
		return fmt.Errorf("Invalid decryption parameters in secret %s: %s", text, err)
	}

	s.ciphertext = internal.Ciphertext(tokens[2])
	return nil
}

// NewSecret creates a Secret object from a string
func NewSecret(textSecret string) (Secret, error) {
	secret := Secret{}
	err := secret.UnmarshalText([]byte(textSecret))
	return secret, err
}
