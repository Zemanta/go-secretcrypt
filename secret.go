package secretcrypt

import (
	"fmt"
	"strings"

	"github.com/Zemanta/go-secretcrypt/internal"
)

// StrictSecret represents an encrypted secret that is decrypted on demand.
// Decrypting this secret may incur a side-effect such as a call to a remote
// service for decryption.
type StrictSecret struct {
	crypter       internal.Crypter
	ciphertext    internal.Ciphertext
	decryptParams internal.DecryptParams
}

// Decrypt decrypts the secret and returns the plaintext. Calling Decrypt()
// may incur side effects such as a call to a remote service for decryption.
func (s *StrictSecret) Decrypt() (string, error) {
	if s.crypter == nil || s.ciphertext == "" {
		return "", nil
	}
	var err error
	plaintext, err := s.crypter.Decrypt(s.ciphertext, s.decryptParams)
	return plaintext, err
}

// MarshalText marshalls the secret into its textual representation.
func (s *StrictSecret) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf(
		"%s:%s:%s",
		s.crypter.Name(),
		internal.UnparseDecryptParams(s.decryptParams),
		s.ciphertext,
	)), nil
}

// UnmarshalText loads the secret from its textual representation.
func (s *StrictSecret) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return nil
	}
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

// AppendParameters sets given decryption parameters.
func (s *StrictSecret) AppendParameters(decryptParams internal.DecryptParams) {
	for key, value := range decryptParams {
		s.decryptParams[key] = value
	}
}

// String ensures plaintext is not leaked when formatting the StrictSecret object
// with %s.
func (s StrictSecret) String() string {
	return string(s.ciphertext)
}

// GoString ensures plaintext is not leaked when formatting the StrictSecret object
// with %#v.
func (s StrictSecret) GoString() string {
	return string(s.ciphertext)
}

// LoadStrictSecret loads a StrictSecret from a string.
func LoadStrictSecret(textStrictSecret string) (StrictSecret, error) {
	secret := StrictSecret{}
	err := secret.UnmarshalText([]byte(textStrictSecret))
	return secret, err
}

// Secret represents a secret that is eagerly decrypted on object creation.
// After that, using this secret does not incur any side effects.
type Secret struct {
	secret    string
	plaintext string
}

// Get returns the secret in plain text. Calling Get() does not incur any side
// effects.
func (s Secret) Get() string {
	return s.plaintext
}

// MarshalText marshalls the secret into its textual representation.
func (s *Secret) MarshalText() (text []byte, err error) {
	return []byte(s.secret), nil
}

// UnmarshalText loads the secret from its textual representation.
func (s *Secret) UnmarshalText(text []byte) error {
	var strictSecret StrictSecret
	err := strictSecret.UnmarshalText(text)
	if err != nil {
		return err
	}
	s.plaintext, err = strictSecret.Decrypt()
	return err
}

// String ensures plaintext is not leaked when formatting the Secret object
// with %s.
func (s Secret) String() string {
	return "<redacted>"
}

// GoString ensures plaintext is not leaked when formatting the Secret object
// with %#v.
func (s Secret) GoString() string {
	return "<redacted>"
}

// LoadSecret loads a Secret from a string.
func LoadSecret(textSecret string) (Secret, error) {
	secret := Secret{}
	err := secret.UnmarshalText([]byte(textSecret))
	return secret, err
}
