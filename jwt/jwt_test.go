package jwt

import (
	"log"
	"testing"

	"github.com/greyaxis/auth/roles"
)

const (
	TEST_JWT_SECRET       string = "supersecret"
	TEST_ADMIN_JWT_SECRET string = "supersecretforadmin"
)

func TestSign(t *testing.T) {

	var claims MyCustomClaims
	claims.Role = roles.RoleCustomer
	claims.ID = "1"

	token, err := Sign(&claims, []byte(TEST_JWT_SECRET))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

}

func TestVerifyWithSign(t *testing.T) {
	var claims MyCustomClaims
	claims.Role = roles.RoleCustomer
	claims.ID = "1"

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
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiUm9sZSI6ImF1dGhvcml6ZWRfcGVyc29uIn0.z2AXUHibnSrFrUV7doTMlHxRKItS4SHkG23F417DVzI"

	claimsAfterVerification, errOnVerify := Verify(token, []byte(TEST_JWT_SECRET))
	if errOnVerify != nil {
		t.Fatal("err while verifying ", errOnVerify)
	}
	t.Log(claimsAfterVerification)
	log.Println(claimsAfterVerification)
}
