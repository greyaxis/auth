package auth

import (
	"fmt"
	"strings"

	"github.com/kataras/iris/v12"
)

func ReadJWTFromHeaders(ctx iris.Context, secret string) (*JWTClaims, error) {

	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {
		fmt.Println("no headers")
		return nil, fmt.Errorf("no headers")
	}

	if headers.Authorization == "" {
		fmt.Println("headers empty")
		return nil, fmt.Errorf("empty headers")
	}

	// TOKEN WITH REMOVED ALL SPACES FROM TOKEN BECAUSE TOKEN WILL BE IN FORMAT eg. Bearer ey....
	token := strings.ReplaceAll(headers.Authorization, " ", "")
	// IF STARTS WITH BEARER REMOVE THE BEARER
	if strings.HasPrefix(token, "Bearer") {
		token = strings.Replace(token, "Bearer", "", 1)
	}
	if strings.HasPrefix(token, "bearer") {
		token = strings.Replace(token, "bearer", "", 1)
	}

	fmt.Println(token)
	claims, errWhileVerifying := Verify(token, []byte(secret))
	fmt.Println(claims, errWhileVerifying)
	if errWhileVerifying != nil {
		return nil, errReadingHeaders
	}

	return claims, nil

}
