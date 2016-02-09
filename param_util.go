package secretcrypt

import (
	"net/url"
	"strings"

	"github.com/fatih/structs"
	"github.com/mitchellh/mapstructure"
)

func parseDecryptParams(s string) (decryptParams, error) {
	vals, err := url.ParseQuery(s)
	if err != nil {
		return nil, err
	}

	params := make(decryptParams)
	for k, v := range vals {
		params[k] = v[0]
	}
	return params, nil
}

func decodeEncryptParams(source encryptParams, target interface{}) error {
	err := mapstructure.Decode(source, target)
	return err
}

func decodeDecryptParams(source decryptParams, target interface{}) error {
	err := mapstructure.Decode(source, target)
	return err
}

func encodeDecryptParams(source interface{}) decryptParams {
	m := structs.Map(source)
	lowercased := make(decryptParams)
	for k, v := range m {
		lowercased[strings.ToLower(k)] = v.(string)
	}
	return lowercased
}
