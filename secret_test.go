package secretcrypt

import (
	"flag"
	"os"
	"testing"

	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	internal.CryptersMap["plain"] = internal.PlainCrypter{}
	flag.Parse()
	os.Exit(m.Run())
}

func assertSecretValid(t *testing.T, secret *Secret) {
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
	assertSecretValid(t, &secret)
}

func TestNewSecret(t *testing.T) {
	secret, err := LoadSecret("plain:k1=v1&k2=v2:my-abc")
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

	secret, err := LoadSecret("mock:k1=v1&k2=v2:my-abc")
	assert.NoError(t, err)

	plaintext, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext, "myplaintext")
	mockCrypter.AssertExpectations(t)
}

func TestCaching(t *testing.T) {
	mockCrypter := &internal.MockCrypter{}
	internal.CryptersMap["mock"] = mockCrypter
	mockCrypter.On(
		"Decrypt",
		internal.Ciphertext("my-abc"),
		internal.DecryptParams{
			"k1": "v1",
			"k2": "v2",
		}).Return("myplaintext", nil)

	secret, err := LoadSecret("mock:k1=v1&k2=v2:my-abc")
	assert.NoError(t, err)

	plaintext, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext, "myplaintext")
	plaintext2, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext2, "myplaintext")

	mockCrypter.AssertExpectations(t)
	mockCrypter.AssertNumberOfCalls(t, "Decrypt", 1)
}

func TestEmptySecret(t *testing.T) {
	zero := &Secret{}
	emptyStr, err := LoadSecret("")
	assert.NoError(t, err)
	for _, secret := range []*Secret{zero, emptyStr} {
		plaintext, err := secret.Decrypt()
		assert.NoError(t, err)
		assert.Equal(t, plaintext, "")
	}
}
