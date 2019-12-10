//go:generate mockery -inpkg -name=KMSAPI

package internal

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type KMSCrypter struct{}

var kmsClients = make(map[string]kmsiface.KMSAPI)
var clientsLock sync.RWMutex

// KMSAPI wraps kmsiface.KMSAPI so that we can generate mock
type KMSAPI interface {
	kmsiface.KMSAPI
}

func (c KMSCrypter) Name() string {
	return "kms"
}

func (c KMSCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	region, ok := encryptParams["region"]
	if !ok {
		return Ciphertext(""), nil, fmt.Errorf("Missing region parameter!")
	}

	keyID, ok := encryptParams["keyID"]
	if !ok {
		return Ciphertext(""), nil, fmt.Errorf("Missing keyID parameter!")
	}

	resp, err := kmsClient(region).Encrypt(
		&kms.EncryptInput{
			Plaintext: []byte(plaintext),
			KeyId:     aws.String(keyID),
		},
	)
	if err != nil {
		return Ciphertext(""), nil, err
	}

	ciphertext := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	decryptParams := DecryptParams{"region": region}
	return Ciphertext(ciphertext), decryptParams, nil
}

func (c KMSCrypter) Decrypt(ciphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	region, ok := decryptParams["region"]
	if !ok {
		return "", fmt.Errorf("Missing region parameter!")
	}

	ciphertextBlob, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return "", err
	}

	resp, err := kmsClient(region).Decrypt(
		&kms.DecryptInput{
			CiphertextBlob: ciphertextBlob,
		},
	)
	if err != nil {
		return "", err
	}

	return string(resp.Plaintext), nil
}

func kmsClient(region string) kmsiface.KMSAPI {
	clientsLock.RLock()
	client, exists := kmsClients[region]
	clientsLock.RUnlock()
	if exists {
		return client
	}
	clientsLock.Lock()
	defer clientsLock.Unlock()
	client, exists = kmsClients[region]
	if exists {
		return client
	}
	client = kms.New(session.New(), &aws.Config{Region: aws.String(region)})
	kmsClients[region] = client
	return client
}
