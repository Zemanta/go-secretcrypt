package secretcrypt

import (
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type kmsCrypter struct{}

var kmsClients map[string]*kms.KMS
var clientsLock = &sync.RWMutex{}

func (c kmsCrypter) name() string {
	return "plain"
}

func (c kmsCrypter) encrypt(plaintext string, encryptParams encryptParams) (ciphertext, decryptParams) {
	return ciphertext(plaintext), nil
}

func (c kmsCrypter) decrypt(myCiphertext ciphertext, decryptParams decryptParams) string {
	return string(myCiphertext)
}

func kmsClient(region string) *kms.KMS {
	clientsLock.RLock()
	client, exists := kmsClients[region]
	clientsLock.RUnlock()
	if !exists {
		clientsLock.Lock()
		defer clientsLock.Unlock()
		client, exists = kmsClients[region]
		if !exists {
			client := kms.New(session.New(), &aws.Config{Region: aws.String(region)})
			kmsClients[region] = client
		}
	}
	return client
}
