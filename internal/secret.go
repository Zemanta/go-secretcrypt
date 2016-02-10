package internal

import (
	"fmt"
	"strings"

	"github.com/Zemanta/go-secretcrypt"
)

type secret struct {
	crypter       Crypter
	ciphertext    Ciphertext
	decryptParams DecryptParams
}

// NewSecret creates a new secret from individual components
func NewSecret(crypter Crypter, decryptParams DecryptParams, ciphertext Ciphertext) secretcrypt.Secret {
	return &secret{
		crypter:       crypter,
		decryptParams: decryptParams,
		ciphertext:    ciphertext,
	}
}

// Decrypt decrypts the secret
func (s *secret) Decrypt() (string, error) {
	return s.crypter.Decrypt(s.ciphertext, s.decryptParams)
}

// MarshalText marshalls the secret into its textual representation
func (s *secret) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf(
		"%s:%s:%s",
		s.crypter.Name(),
		UnparseDecryptParams(s.decryptParams),
		s.ciphertext,
	)), nil
}

// UnmarshalText loads the secret from its textual representation
func (s *secret) UnmarshalText(text []byte) error {
	tokens := strings.Split(string(text), ":")
	if len(tokens) < 3 {
		return fmt.Errorf("Malformed secret '%s'", text)
	}

	var exists bool
	s.crypter, exists = CryptersMap[tokens[0]]
	if !exists {
		return fmt.Errorf("Invalid crypter name in secret %s", text)
	}

	var err error
	s.decryptParams, err = ParseDecryptParams(tokens[1])
	if err != nil {
		return fmt.Errorf("Invalid decryption parameters in secret %s: %s", text, err)
	}

	s.ciphertext = Ciphertext(strings.Join(tokens[2:], ":"))
	return nil
}

// NewSecretFromString creates a Secret object from a string
func NewSecretFromString(textSecret string) (secretcrypt.Secret, error) {
	secret := &secret{}
	err := secret.UnmarshalText([]byte(textSecret))
	return secret, err
}
