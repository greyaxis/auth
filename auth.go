package auth

import (
	"encoding/base64"
	"strings"

	"github.com/google/uuid"

	"github.com/kataras/iris/v12"
)

type authenticateHeaders struct {
	Authorization string `header:"Authorization"`
}

type authenticationError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type RequestState struct {
	JWTClaims
}

type RequestStateDigiGoldPartner struct {
	JWTClaimsDigiGoldPartner
}

type RequestAdminState struct {
	JWTClaimsAdmin
}
type RequestDigitalBackOfficeState struct {
	JWTClaimsDigitalBackOfficeUser
}

const (
	RequestStateKey string = "state"
)

var (
	JWT_SECRET       string
	ADMIN_JWT_SECRET string
	INTERSVC_API_KEY string
	DebugMode        bool
)

func Init(JWtSecret string, adminJWTSecret string, interSVCAPIKey string, debugMode bool) {
	if JWtSecret == "" || adminJWTSecret == "" {
		panic("empty values provided")
	}
	JWT_SECRET = JWtSecret
	ADMIN_JWT_SECRET = adminJWTSecret
	INTERSVC_API_KEY = interSVCAPIKey
	debugMode = DebugMode
}

func AuthenticateCustomer(ctx iris.Context) {
	err := authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {

		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if headers.Authorization == "" {
		DebugLog("auth : empty headers received")
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

	claims, errWhileVerifying := Verify(token, []byte(JWT_SECRET))
	if errWhileVerifying != nil {
		DebugLog("auth: error occured while verifying the token, err: ", errWhileVerifying)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if claims.Role != RoleCustomer {
		DebugLog("auth: err occured the token has role diffrent than expected that is ", claims.Role)
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
func AuthenticateAdmin(ctx iris.Context) {
	err := authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {

		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if headers.Authorization == "" {
		DebugLog("auth : empty headers received")
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

	c := JWTClaimsAdmin{}

	claims, errWhileVerifying := c.Verify(token, []byte(ADMIN_JWT_SECRET))
	if errWhileVerifying != nil {
		DebugLog("auth: error occured while verifying the token, err: ", errWhileVerifying)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if claims.Role != RoleAdmin {
		DebugLog("auth: err occured the token has role diffrent than expected that is ", claims.Role)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}
	var reqState = RequestAdminState{
		*claims,
	}

	ctx.Values().Set(RequestStateKey, reqState)
	ctx.RegisterDependency(reqState)
	ctx.Next()
}
func AuthenticateAuthorizedPerson(ctx iris.Context) {
	err := authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {

		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if headers.Authorization == "" {
		DebugLog("auth : empty headers received")
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

	claims, errWhileVerifying := Verify(token, []byte(JWT_SECRET))
	if errWhileVerifying != nil {
		DebugLog("auth: error occured while verifying the token, err: ", errWhileVerifying)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	var reqState = RequestState{
		*claims,
	}

	if claims.Role != RoleAuthorizedPerson {
		DebugLog("auth: err occured the token has role diffrent than expected that is ", claims.Role)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}
	ctx.Values().Set(RequestStateKey, reqState)
	ctx.RegisterDependency(reqState)
	ctx.Next()
}

func AuthenticateDigiGoldPartner(ctx iris.Context) {
	err := authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {

		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if headers.Authorization == "" {
		DebugLog("auth : empty headers received")
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

	c := JWTClaimsDigiGoldPartner{}
	claims, errWhileVerifying := c.Verify(token, []byte(JWT_SECRET))
	if errWhileVerifying != nil {
		DebugLog("auth: error occured while verifying the token, err: ", errWhileVerifying)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	var reqState = RequestStateDigiGoldPartner{
		*claims,
	}

	if claims.Role != RoleDigiGoldPartner {
		DebugLog("auth: err occured the token has role diffrent than expected that is ", claims.Role)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}
	ctx.Values().Set(RequestStateKey, reqState)
	ctx.RegisterDependency(reqState)
	ctx.Next()
}
func AuthenticateDigitalBackOfficeUser(ctx iris.Context) {
	err := authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	var headers authenticateHeaders
	errReadingHeaders := ctx.ReadHeaders(&headers)
	if errReadingHeaders != nil {

		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	if headers.Authorization == "" {
		DebugLog("auth : empty headers received")
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

	c := JWTClaimsDigitalBackOfficeUser{}
	claims, errWhileVerifying := c.Verify(token, []byte(JWT_SECRET))
	if errWhileVerifying != nil {
		DebugLog("auth: error occured while verifying the token, err: ", errWhileVerifying)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}

	var reqState = RequestDigitalBackOfficeState{
		*claims,
	}

	if claims.Role != RoleDigitalBackOfficeUser {
		DebugLog("auth: err occured the token has role diffrent than expected that is ", claims.Role)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", err))
		return
	}
	ctx.Values().Set(RequestStateKey, reqState)
	ctx.RegisterDependency(reqState)
	ctx.Next()
}

type GatewayHeaders struct {
	Authorization string    `header:"Authorization"`
	ID            int       `header:"id"`
	Role          string    `header:"role"`
	AgentID       string    `header:"agendID"`
	SessionID     uuid.UUID `header:"sessionID"`
}

var (
	unauthorizedErr = authenticationError{
		Error:   "Unauthorized",
		Message: "access denied",
	}
	unknownHeaderTypeErr = authenticationError{
		Error:   "This header type is not supported",
		Message: "access denied",
	}
)

func Authenticate(ctx iris.Context) {
	var headers GatewayHeaders
	err := ctx.ReadHeaders(&headers)
	if err != nil {
		DebugLog("err reading headers from auth.Authenticate, err: ", err)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().
			Key("error", unauthorizedErr))
		return
	}
	DebugLog("received headers: ", ctx.Request().Header)

	parts := strings.Split(headers.Authorization, " ")
	if len(parts) != 2 {
		DebugLog("token was splitted but the legnth is not enough setting request as public request, parts:", parts)
		var state RequestState
		state.Role = RolePublic
		ctx.Values().Set(RequestStateKey, state)
		ctx.RegisterDependency(state)
		ctx.Next()
		return
	}
	if strings.ToLower(parts[0]) != "bearer" {
		DebugLog("token type was not bearer")
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().Key("error", unknownHeaderTypeErr))
		return
	}

	token := parts[1]
	DebugLog("token in base64 : ", token)
	byteToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		DebugLog("byteToken, err:=base64.StdEncoding.DecodeString(token), err: ", err)
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().Key("error", unauthorizedErr))
		return
	}

	if strings.Compare(strings.TrimSpace(string(byteToken)), INTERSVC_API_KEY) != 0 {
		DebugLog("comparison failed")
		DebugLog("token received: ", string(byteToken), " len:", len(string(byteToken)))
		DebugLog("token actual: ", INTERSVC_API_KEY, " len:", len(INTERSVC_API_KEY))
		ctx.StopWithProblem(iris.StatusUnauthorized, iris.NewProblem().Key("error", unauthorizedErr))
		return
	}

	var state RequestState
	state.ID = uint(headers.ID)
	state.AgentID = headers.AgentID
	state.SessionID = headers.SessionID
	state.Role = Role(headers.Role)
	ctx.Values().Set(RequestStateKey, state)
	ctx.RegisterDependency(state)
	ctx.Next()

}
