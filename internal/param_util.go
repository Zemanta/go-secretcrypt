package internal

import (
	"net/url"
	"strings"

	"github.com/fatih/structs"
	"github.com/mitchellh/mapstructure"
)

// ParseDecryptParams parses the URL encoded parameters into a map
func ParseDecryptParams(s string) (DecryptParams, error) {
	vals, err := url.ParseQuery(s)
	if err != nil {
		return nil, err
	}

	params := make(DecryptParams)
	for k, v := range vals {
		params[k] = v[0]
	}
	return params, nil
}

// UnparseDecryptParams parses the URL encoded parameters into a map
func UnparseDecryptParams(decryptParams DecryptParams) string {
	values := make(url.Values)
	for k, v := range decryptParams {
		values.Add(k, v)
	}
	return values.Encode()
}

func decodeEncryptParams(source EncryptParams, target interface{}) error {
	err := mapstructure.Decode(source, target)
	return err
}

func decodeDecryptParams(source DecryptParams, target interface{}) error {
	err := mapstructure.Decode(source, target)
	return err
}

func encodeDecryptParams(source interface{}) DecryptParams {
	m := structs.Map(source)
	lowercased := make(DecryptParams)
	for k, v := range m {
		lowercased[strings.ToLower(k)] = v.(string)
	}
	return lowercased
}
