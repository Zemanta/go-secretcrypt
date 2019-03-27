package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
)

func TestKms(t *testing.T) {
	mockKMS := &MockKMSAPI{}
	defer mockKMS.AssertExpectations(t)
	kmsClients["myregion:myprofile"] = mockKMS
	kmsCrypter := KMSCrypter{}

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
	secret, myDecryptParams, err := kmsCrypter.Encrypt("mypass", map[string]string{
		"region":  "myregion",
		"profile": "myprofile",
		"keyID":   "mykey",
	})
	assert.Equal(t, myDecryptParams, DecryptParams{
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
	myDecryptParams["profile"] = "myprofile"

	plaintext, err := kmsCrypter.Decrypt(secret, myDecryptParams)
	assert.Nil(t, err)
	assert.Equal(t, "mypass", plaintext)
}

func TestKmsDefaultProfile(t *testing.T) {
	mockKMS := &MockKMSAPI{}
	defer mockKMS.AssertExpectations(t)
	kmsClients["myregion:default"] = mockKMS
	kmsCrypter := KMSCrypter{}

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
	secret, myDecryptParams, err := kmsCrypter.Encrypt("mypass", map[string]string{
		"region": "myregion",
		"keyID":  "mykey",
	})
	assert.Equal(t, myDecryptParams, DecryptParams{
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

	plaintext, err := kmsCrypter.Decrypt(secret, myDecryptParams)
	assert.Nil(t, err)
	assert.Equal(t, "mypass", plaintext)
}
