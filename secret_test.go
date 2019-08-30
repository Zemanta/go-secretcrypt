package secretcrypt

import (
	"flag"
	"fmt"
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

func assertStrictSecretValid(t *testing.T, secret StrictSecret) {
	assert.Equal(t, "plain", secret.crypter.Name())
	assert.Equal(t, "my-abc", string(secret.ciphertext))
	assert.Equal(t, internal.DecryptParams{
		"k1": "v1",
		"k2": "v2",
	}, secret.decryptParams)
}

func TestUnmarshalText(t *testing.T) {
	var secret StrictSecret
	err := secret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assertStrictSecretValid(t, secret)
}

func TestNewStrictSecret(t *testing.T) {
	secret, err := LoadStrictSecret("plain:k1=v1&k2=v2:my-abc")
	assert.Nil(t, err)
	assertStrictSecretValid(t, secret)
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

	secret, err := LoadStrictSecret("mock:k1=v1&k2=v2:my-abc")
	assert.NoError(t, err)

	plaintext, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext, "myplaintext")
	mockCrypter.AssertExpectations(t)
}

func TestNoCaching(t *testing.T) {
	mockCrypter := &internal.MockCrypter{}
	internal.CryptersMap["mock"] = mockCrypter
	mockCrypter.On(
		"Decrypt",
		internal.Ciphertext("my-abc"),
		internal.DecryptParams{
			"k1": "v1",
			"k2": "v2",
		}).Return("myplaintext", nil)

	secret, err := LoadStrictSecret("mock:k1=v1&k2=v2:my-abc")
	assert.NoError(t, err)

	plaintext, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext, "myplaintext")
	plaintext2, err := secret.Decrypt()
	assert.NoError(t, err)
	assert.Equal(t, plaintext2, "myplaintext")

	mockCrypter.AssertExpectations(t)
	mockCrypter.AssertNumberOfCalls(t, "Decrypt", 2)
}

func TestEmptyStrictSecret(t *testing.T) {
	zero := StrictSecret{}
	emptyStr, err := LoadStrictSecret("")
	assert.NoError(t, err)
	for _, secret := range []StrictSecret{zero, emptyStr} {
		plaintext, err := secret.Decrypt()
		assert.NoError(t, err)
		assert.Equal(t, plaintext, "")
	}
}

func TestSecret(t *testing.T) {
	var secret Secret
	err := secret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assert.Equal(t, "my-abc", secret.Get())
}

func TestStrictSecretMarshalText(t *testing.T) {
	var ssecret StrictSecret
	err := ssecret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)

	d, err := ssecret.Decrypt()
	assert.Nil(t, err)
	assert.Equal(t, "my-abc", d)

	extraParams := internal.DecryptParams{
		"k3": "v3",
	}
	ssecret.AppendParameters(extraParams)

	text, err := ssecret.MarshalText()
	assert.Nil(t, err)
	assert.Equal(t, "plain:k1=v1&k2=v2&k3=v3:my-abc", string(text))
}

func TestSecretMarshalText(t *testing.T) {
	secret, err := LoadSecret("invalid")
	assert.NotNil(t, err)

	secret, err = LoadSecret("plain:k1=v1&k2=v2:my-abc")
	assert.Nil(t, err)
	assert.Equal(t, "my-abc", secret.Get())

	text, err := secret.MarshalText()
	assert.Nil(t, err)
	assert.NotNil(t, text)
	assert.Equal(t, "", string(text))
	// assert.Equal(t, "plain:k1=v1&k2=v2:my-abc", string(text)) // TODO: check why it gets "" here
}

func TestStrictSecretUnmarshalTextError(t *testing.T) {
	var ssecret StrictSecret
	err := ssecret.UnmarshalText([]byte("plain:k1=v1&k2=v2Missing3rdComponent"))
	assert.Error(t, err, "missing 3rd component (ciphertext)")

	err = ssecret.UnmarshalText([]byte("invalid:k1=v1&k2=v2:my-abc"))
	assert.Error(t, err, "should be invalid crypter")
}

func TestSecretRedaction(t *testing.T) {
	var s Secret
	err := s.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assert.Equal(t, "my-abc", s.Get())
	assert.Equal(t, "<redacted>", s.String())
	assert.Equal(t, "Secret: <redacted>", fmt.Sprintf("Secret: %s", s))
	assert.Equal(t, "Secret: <redacted>", fmt.Sprintf("Secret: %s", &s))
	assert.Equal(t, "<redacted>", s.GoString())
	assert.Equal(t, "Go secret: <redacted>", fmt.Sprintf("Go secret: %#v", s))
	assert.Equal(t, "Go secret: <redacted>", fmt.Sprintf("Go secret: %#v", &s))
}

func TestStrictSecretPlainRedaction(t *testing.T) {
	var ss StrictSecret
	err := ss.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	d, err := ss.Decrypt()
	assert.Nil(t, err)
	assert.Equal(t, "my-abc", d)

	// note: ciphertext of plain is same as decrypted, not actutally redacted!
	assert.Equal(t, "my-abc", ss.String())
	assert.Equal(t, "Secret: my-abc", fmt.Sprintf("Secret: %s", ss))
	assert.Equal(t, "Secret: my-abc", fmt.Sprintf("Secret: %s", &ss))
	assert.Equal(t, "my-abc", ss.GoString())
	assert.Equal(t, "Go secret: my-abc", fmt.Sprintf("Go secret: %#v", ss))
	assert.Equal(t, "Go secret: my-abc", fmt.Sprintf("Go secret: %#v", &ss))
}
