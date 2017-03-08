package internal

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type KMSCrypter struct{}

var kmsClients = make(map[string]kmsiface.KMSAPI)
var clientsLock sync.RWMutex

func (c KMSCrypter) Name() string {
	return "kms"
}

func (c KMSCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	region, ok := encryptParams["region"]
	if !ok {
		return Ciphertext(""), nil, fmt.Errorf("Missing region parameter!")
	}

	profile, ok := encryptParams["profile"]
	if !ok {
		return Ciphertext(""), nil, fmt.Errorf("Missing profile parameter!")
	}

	keyID, ok := encryptParams["keyID"]
	if !ok {
		return Ciphertext(""), nil, fmt.Errorf("Missing keyID parameter!")
	}

	resp, err := kmsClient(region, profile).Encrypt(
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

	profile, ok := decryptParams["profile"]
	if !ok {
		return "", fmt.Errorf("Missing profile parameter!")
	}

	ciphertextBlob, err := base64.StdEncoding.DecodeString(string(ciphertext))
	resp, err := kmsClient(region, profile).Decrypt(
		&kms.DecryptInput{
			CiphertextBlob: ciphertextBlob,
		},
	)
	if err != nil {
		return "", err
	}

	return string(resp.Plaintext), nil
}

func kmsClient(region string, profile string) kmsiface.KMSAPI {
	key := region + ":" + profile

	clientsLock.RLock()
	client, exists := kmsClients[key]
	clientsLock.RUnlock()
	if exists {
		return client
	}

	clientsLock.Lock()
	client = kms.New(session.New(), &aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile),
	})
	kmsClients[region] = client
	clientsLock.Unlock()

	return client
}
