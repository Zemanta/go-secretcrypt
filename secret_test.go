package secretcrypt

import (
	"testing"

	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/stretchr/testify/assert"
)

func assertSecretValid(t *testing.T, secret Secret) {
	assert.Equal(t, "plain", secret.crypter.Name())
	assert.Equal(t, "my-abc", string(secret.ciphertext))
	assert.Equal(t, internal.DecryptParams{
		"k1": "v1",
		"k2": "v2",
	}, secret.decryptParams)
}

func TestUnmarshalText(t *testing.T) {
	var secret Secret
	err := secret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assertSecretValid(t, secret)
}

func TestNewSecret(t *testing.T) {
	secret, err := NewSecret("plain:k1=v1&k2=v2:my-abc")
	assert.Nil(t, err)
	assertSecretValid(t, secret)
}

func TestDecrypt(t *testing.T) {
	mockCrypter := &internal.MockCrypter{}
	internal.CryptersMap["mock"] = mockCrypter
	mockCrypter.On(
		"Decrypt",
		internal.Ciphertext("my-abc"),
		internal.DecryptParams{
			"k1": "v1",
			"k2": "v2",
		}).Return("myplaintext", nil)

	secret, err := NewSecret("mock:k1=v1&k2=v2:my-abc")
	assert.NoError(t, err)

	plaintext, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext, "myplaintext")
	mockCrypter.AssertExpectations(t)
}
