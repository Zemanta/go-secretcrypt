package secretcrypt

import (
	"encoding"
	"fmt"
	"net/url"
	"strings"
)

// Secret represents an encrypted secret
type Secret interface {
	Decrypt() string
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

type secret struct {
	crypter       crypter
	ciphertext    ciphertext
	decryptParams decryptParams
}

// Decrypt decrypts the secret
func (s *secret) Decrypt() string {
	return s.crypter.decrypt(s.ciphertext, s.decryptParams)
}

// MarshalText marshalls the secret into its textual representation
func (s *secret) MarshalText() (text []byte, err error) {
	return []byte(fmt.Sprintf("%s:%s", s.crypter.name(), s.ciphertext)), nil
}

// UnmarshalText loads the secret from its textual representation
func (s *secret) UnmarshalText(text []byte) error {
	tokens := strings.Split(string(text), ":")
	if len(tokens) < 3 {
		return fmt.Errorf("Malformed secret '%s'", text)
	}
	crypterName := tokens[0]
	myCrypter, exists := cryptersMap[crypterName]
	if !exists {
		return fmt.Errorf("Invalid crypter name in secret %s", text)
	}
	s.crypter = myCrypter

	paramValues, err := url.ParseQuery(tokens[1])
	if err != nil {
		return fmt.Errorf("Invalid decryption parameters in secret %s", text)
	}
	s.decryptParams = make(decryptParams)
	for k, v := range paramValues {
		s.decryptParams[k] = v[0]
	}

	s.ciphertext = ciphertext(strings.Join(tokens[2:], ":"))
	return nil
}

// NewSecret creates a new Secret
func NewSecret(myCrypter crypter, myCiphertext ciphertext) Secret {
	return &secret{
		crypter:    myCrypter,
		ciphertext: myCiphertext,
	}
}

// NewSecretFromString creates a Secret object from a string
func NewSecretFromString(textSecret string) (Secret, error) {
	var secret Secret
	err := secret.UnmarshalText([]byte(textSecret))
	return secret, err
}
