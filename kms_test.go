package secretcrypt

import (
	"testing"

	"github.com/Zemanta/go-secretcrypt/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

func TestKms(t *testing.T) {
	mockKMS := &mocks.KMSAPI{}
	defer mockKMS.AssertExpectations(t)
	kmsClients["myregion"] = mockKMS
	kmsCrypter := kmsCrypter{}

	mockKMS.On("Encrypt",
		&kms.EncryptInput{
			KeyId:     aws.String("mykey"),
			Plaintext: []byte("mypass"),
		},
	).Return(
		&kms.EncryptOutput{
			CiphertextBlob: []byte("myciphertextblob"),
		},
		nil,
	)
	secret, myDecryptParams, err := kmsCrypter.encrypt("mypass", map[string]string{
		"region": "myregion",
		"keyID":  "mykey",
	})
	assert.Equal(t, myDecryptParams, decryptParams{
		"region": "myregion",
	})
	assert.Nil(t, err)

	mockKMS.On("Decrypt",
		&kms.DecryptInput{
			CiphertextBlob: []byte("myciphertextblob"),
		},
	).Return(
		&kms.DecryptOutput{
			Plaintext: []byte("mypass"),
		},
		nil,
	)

	plaintext, err := kmsCrypter.decrypt(secret, myDecryptParams)
	assert.Nil(t, err)
	assert.Equal(t, "mypass", plaintext)
}
