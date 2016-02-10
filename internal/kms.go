package internal

import (
	"encoding/base64"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type KMSCrypter struct{}

var kmsClients = make(map[string]kmsiface.KMSAPI)
var clientsLock sync.RWMutex

type kmsEncryptParams struct {
	Region string
	KeyID  string
}

type kmsDecryptParams struct {
	Region string
}

func (c KMSCrypter) Name() string {
	return "kms"
}

func (c KMSCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	var params kmsEncryptParams
	err := decodeEncryptParams(encryptParams, &params)
	if err != nil {
		return Ciphertext(""), nil, err
	}

	resp, err := kmsClient(params.Region).Encrypt(
		&kms.EncryptInput{
			Plaintext: []byte(plaintext),
			KeyId:     aws.String(params.KeyID),
		},
	)
	if err != nil {
		return Ciphertext(""), nil, err
	}

	ciphertext := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	myDecryptParams := kmsDecryptParams{Region: params.Region}
	return Ciphertext(ciphertext), encodeDecryptParams(myDecryptParams), nil
}

func (c KMSCrypter) Decrypt(ciphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	var params kmsDecryptParams
	decodeDecryptParams(decryptParams, &params)

	ciphertextBlob, err := base64.StdEncoding.DecodeString(string(ciphertext))
	resp, err := kmsClient(params.Region).Decrypt(
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
	if !exists {
		clientsLock.Lock()
		defer clientsLock.Unlock()
		client, exists = kmsClients[region]
		if !exists {
			client = kms.New(session.New(), &aws.Config{Region: aws.String(region)})
			kmsClients[region] = client
		}
	}
	return client
}
