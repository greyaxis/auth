package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// takes authorizationToken which comes in api in base64 request and actual token in string to match
func AuthenticateSVC(authorizationToken string, tokenToMatch string) error {
	if authorizationToken == "" {
		return fmt.Errorf("authorizationToken is empty")
	}

	parts := strings.Split(authorizationToken, " ")
	if len(parts) != 2 {
		return fmt.Errorf("unknown type header")
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return fmt.Errorf("unknown type header")
	}

	tokenInBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("error while decoding")
	}

	token := strings.ReplaceAll(string(tokenInBytes), " ", "")
	if tokenToMatch != strings.TrimSpace(token) {
		return fmt.Errorf("received token from api %v and actual %v", token, tokenToMatch)
	}
	return nil
}
