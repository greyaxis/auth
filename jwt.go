package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// TODO: PENDING IMPLIMNETATION CHECK
type JWTClaims struct {
	jwt.RegisteredClaims
	Role Role
}

func Sign(claims *JWTClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)

	fmt.Println(tokenString, err)

	if err != nil {
		return tokenString, err
	}

	return tokenString, nil
}

func Verify(tokenString string, secret []byte) (*JWTClaims, error) {

	token, errWhileVerifying := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if errWhileVerifying != nil {
		return &JWTClaims{}, errWhileVerifying
	} else if claims, ok := token.Claims.(*JWTClaims); ok {
		return claims, nil
	} else {
		// log.Fatal("unknown claims type, cannot proceed")

		return &JWTClaims{}, errors.New("unknown claims type, cannot proceed")
	}
}