package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/docopt/docopt-go"
	"github.com/mattn/go-isatty"
)

func encryptSecret(crypter internal.Crypter, plaintext string, encryptParams internal.EncryptParams) (string, error) {
	ciphertext, decryptParams, err := crypter.Encrypt(plaintext, encryptParams)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"%s:%s:%s",
		crypter.Name(),
		internal.UnparseDecryptParams(decryptParams),
		ciphertext,
	), nil
}

func main() {
	usage := `Encrypts secrets. Reads secrets as user input or from standard input.

Usage:
  encrypt-secret [options] kms <key_id>
  encrypt-secret [options] local
  encrypt-secret [options] password

Options:
  --help
  --region=<region_name>    AWS Region Name [default: us-east-1]
  --multiline               Multiline input (read stdin bytes until EOF)
`

	arguments, _ := docopt.Parse(usage, nil, true, "0.1", false)

	var crypter internal.Crypter
	var encryptParams = make(internal.EncryptParams)
	if arguments["kms"].(bool) {
		crypter = internal.CryptersMap["kms"]
		encryptParams["region"] = arguments["--region"].(string)
		encryptParams["keyID"] = arguments["<key_id>"].(string)
	} else if arguments["local"].(bool) {
		crypter = internal.CryptersMap["local"]
	} else if arguments["password"].(bool) {
		crypter = internal.CryptersMap["password"]
	}

	// do not print prompt if input is being piped
	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "Enter plaintext: ")
	}

	var plaintext string
	var err error
	if arguments["--multiline"].(bool) {
		fmt.Fprintf(os.Stderr, "\n")
		var plainbytes []byte
		plainbytes, err = ioutil.ReadAll(os.Stdin)
		plaintext = string(plainbytes)
	} else {
		_, err = fmt.Scanln(&plaintext)
	}
	if err != nil {
		fmt.Println("Invalid plaintext input!", err)
		return
	}
	secret, err := encryptSecret(crypter, plaintext, encryptParams)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	fmt.Println(secret)
}
