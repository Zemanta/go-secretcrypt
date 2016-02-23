package secretcrypt

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Zemanta/go-secretcrypt/internal"
)

// Secret represents an encrypted secret.
type Secret struct {
	once          sync.Once
	crypter       internal.Crypter
	ciphertext    internal.Ciphertext
	plaintext     string
	decryptParams internal.DecryptParams
}

// Decrypt decrypts the secret and returns the plaintext.
func (s *Secret) Decrypt() (string, error) {
	if s.crypter == nil || s.ciphertext == "" {
		return "", fmt.Errorf("Cannot decrypt a zero secret!")
	}
	var err error
	s.once.Do(func() {
		s.plaintext, err = s.crypter.Decrypt(s.ciphertext, s.decryptParams)
	})
	return s.plaintext, err
}

// MarshalText marshalls the secret into its textual representation.
func (s *Secret) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf(
		"%s:%s:%s",
		s.crypter.Name(),
		internal.UnparseDecryptParams(s.decryptParams),
		s.ciphertext,
	)), nil
}

// UnmarshalText loads the secret from its textual representation.
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

func (s *Secret) String() string {
	return string(s.ciphertext)
}

// GoString ensures plaintext is not leaked when formatting the Secret object
// with %#v.
func (s *Secret) GoString() string {
	return string(s.ciphertext)
}

// LoadSecret loads a Secret from a string.
func LoadSecret(textSecret string) (*Secret, error) {
	secret := &Secret{}
	err := secret.UnmarshalText([]byte(textSecret))
	return secret, err
}
