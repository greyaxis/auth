package auth

import (
	"log"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TEST_JWT_SECRET       string = "supersecret"
	TEST_ADMIN_JWT_SECRET string = "supersecretforadmin"
)

func TestSign(t *testing.T) {

	var claims = JWTClaims{
		Role: RoleCustomer,
		ID:   1,
	}

	token, err := Sign(&claims, []byte(TEST_JWT_SECRET))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

}

func TestVerifyWithSign(t *testing.T) {
	var claims JWTClaims
	claims.Role = RoleCustomer
	claims.ID = 2

	token, err := Sign(&claims, []byte(TEST_JWT_SECRET))
	if err != nil {
		t.Fatal("err while signing", err)
	}
	t.Log(token)

	claimsAfterVerification, errOnVerify := Verify(token, []byte(TEST_JWT_SECRET))
	if errOnVerify != nil {
		t.Fatal("err while verifying ", err)
	}
	t.Log(claimsAfterVerification)
	log.Println(claimsAfterVerification)
}

func TestVerify(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiUm9sZSI6ImN1c3RvbWVyIn0.z2ZKLMeOo5JKm2PQZ0v-Ckrc4W_Gww_SUcB8wfpdZzo"

	claimsAfterVerification, errOnVerify := Verify(token, []byte(TEST_JWT_SECRET))
	if errOnVerify != nil {
		t.Fatal("err while verifying ", errOnVerify)
	}
	t.Log(claimsAfterVerification)
	log.Println(claimsAfterVerification)
}

type myCustomClaims struct {
	jwt.RegisteredClaims
	Role    Role
	AgentID string
	ID      uint `json:"id"`
}
