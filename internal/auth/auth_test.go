package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type response struct {
		key string
		err error
	}

	type test struct {
		input http.Header
		want  response
	}

	tests := []test{
		{input: nil, want: response{key: "", err: ErrNoAuthHeaderIncluded}},
		{input: http.Header{"Authorization": []string{"ApiKey foo"}}, want: response{key: "foo", err: nil}},
		{input: http.Header{"Authorization": []string{"Bearer foo"}}, want: response{key: "", err: errors.New("malformed authorization header")}},
	}

	for _, test := range tests {
		got, err := GetAPIKey(test.input)
		results := response{key: got, err: err}

		if results.key != test.want.key && results.err.Error() != test.want.err.Error() {
			t.Errorf("GetAPIKey(%v) = %v, want %v", test.input, results, test.want)
		}
	}
}
