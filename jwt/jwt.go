package jwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greyaxis/auth/roles"
)

// TODO: PENDING IMPLIMNETATION CHECK
type MyCustomClaims struct {
	jwt.RegisteredClaims
	Role roles.Role
}

func Sign(claims *MyCustomClaims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)

	fmt.Println(tokenString, err)

	if err != nil {
		return tokenString, err
	}

	return tokenString, nil
}

func Verify(tokenString string, secret []byte) (*MyCustomClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return &MyCustomClaims{}, err
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		return claims, nil
	} else {
		// log.Fatal("unknown claims type, cannot proceed")

		return &MyCustomClaims{}, errors.New("unknown claims type, cannot proceed")
	}
}
