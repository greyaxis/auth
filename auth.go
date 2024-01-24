package auth

import (
	"log"
	"strings"

	"github.com/greyaxis/auth/jwt"
	"github.com/kataras/iris/v12"
)

type Auth struct {
	JWT_SECRET       string
	ADMIN_JWT_SECRET string
}

type authenticateHeaders struct {
	Authorization string `header:"Authorization"`
}

type authenticationError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type RequestState struct {
	jwt.MyCustomClaims
}

const (
	RequestStateKey string = "state"
)

func (a *Auth) AuthenticateCustomer(ctx iris.Context) {
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {
		err := authenticationError{
			Error:   "Unauthorized",
			Message: "access denies",
		}
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
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

	claims, err := jwt.Verify(token, []byte(a.JWT_SECRET))
	if err != nil {
		log.Println("auth: error occured while verifying the token, err: ", err)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	var reqState = RequestState{
		*claims,
	}
	ctx.Values().Set(RequestStateKey, reqState)
	ctx.RegisterDependency(reqState)
	ctx.Next()
}
