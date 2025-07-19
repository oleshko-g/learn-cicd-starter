package auth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/nalgeon/be"
)

func TestGetAPIKey(t *testing.T) {
	headers := make(http.Header)

	// Missing Authorization header
	authToken, err := GetAPIKey(headers)
	be.Equal(t, authToken, "")
	be.Err(t, err, ErrNoAuthHeaderIncluded)

	// Empty Authorization header
	headers.Set("Authorization", "ApiKey ")
	authToken, err = GetAPIKey(headers)
	be.Equal(t, authToken, "")
	be.Err(t, err, ErrMalformedAuthHeader)

	randomTokenString, err := Make256BitsToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		t.FailNow()
	}

	// No Error
	headers.Set("Authorization", "ApiKey "+randomTokenString)
	authToken, err = GetAPIKey(headers)
	be.Equal(t, authToken, randomTokenString)
	be.Err(t, err, nil)

	// Falformed Token
	headers.Set("Authorization", "ApiKey    "+randomTokenString)
	authToken, err = GetAPIKey(headers)
	be.Equal(t, authToken, "")
	be.Err(t, err, ErrMalformedAuthHeader)
}
