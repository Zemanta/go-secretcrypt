package secretcrypt

import (
	"encoding/base64"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type kmsCrypter struct{}

var kmsClients = make(map[string]kmsiface.KMSAPI)
var clientsLock = &sync.RWMutex{}

type kmsEncryptParams struct {
	Region string
	KeyID  string
}

type kmsDecryptParams struct {
	Region string
}

func (c kmsCrypter) name() string {
	return "kms"
}

func (c kmsCrypter) encrypt(plaintext string, encryptParams encryptParams) (ciphertext, decryptParams, error) {
	var params kmsEncryptParams
	err := decodeEncryptParams(encryptParams, &params)
	if err != nil {
		return ciphertext(""), nil, err
	}

	resp, err := kmsClient(params.Region).Encrypt(
		&kms.EncryptInput{
			Plaintext: []byte(plaintext),
			KeyId:     aws.String(params.KeyID),
		},
	)
	if err != nil {
		return ciphertext(""), nil, err
	}

	myCiphertext := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	myDecryptParams := kmsDecryptParams{Region: params.Region}
	return ciphertext(myCiphertext), encodeDecryptParams(myDecryptParams), nil
}

func (c kmsCrypter) decrypt(myCiphertext ciphertext, decryptParams decryptParams) (string, error) {
	var params kmsDecryptParams
	decodeDecryptParams(decryptParams, &params)

	myCiphertextBlob, err := base64.StdEncoding.DecodeString(string(myCiphertext))
	resp, err := kmsClient(params.Region).Decrypt(
		&kms.DecryptInput{
			CiphertextBlob: myCiphertextBlob,
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
