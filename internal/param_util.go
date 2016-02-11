package internal

import "net/url"

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
