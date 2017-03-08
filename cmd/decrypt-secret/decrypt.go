package main

import (
	"fmt"

	"github.com/Zemanta/go-secretcrypt"
	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/docopt/docopt-go"
)

func decryptSecret(secretStr string, decryptParams internal.DecryptParams) {
	secret, err := secretcrypt.LoadStrictSecret(secretStr)
	if err != nil {
		fmt.Println("Error parsing secret:", err)
		return
	}
	secret.AppendParameters(decryptParams)

	plaintext, err := secret.Decrypt()
	if err != nil {
		fmt.Println("Error decrypting secret", secretStr, ", err:", err)
		return
	}
	fmt.Println(plaintext)
}

func main() {
	usage := `Encrypted secrets.

Usage:
  decrypt-secret [options] <secret>

Options:
  --help
  --profile=<profile>		    AWS Profile Name [default: default]
`
	arguments, _ := docopt.Parse(usage, nil, true, "0.1", false)

	var decryptParams = make(internal.DecryptParams)
	decryptParams["profile"] = arguments["--profile"].(string)

	decryptSecret(arguments["<secret>"].(string), decryptParams)
}
