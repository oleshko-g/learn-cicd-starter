package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

var (
	ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
	ErrMalformedAuthHeader  = errors.New("malformed authorization header")
)

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}

	if splitAuth := strings.Split(authHeader, " "); len(splitAuth) == 2 &&
		splitAuth[0] == "ApiKey" && splitAuth[1] != "" {
		return splitAuth[1], nil
	}

	return "", ErrMalformedAuthHeader

}

func Make256BitsToken() (string, error) {
	randomData := make([]byte, 32)
	rand.Read(randomData)
	return hex.EncodeToString(randomData), nil
}
