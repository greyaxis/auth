package auth

import (
	"log"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	token := "eyq"
	res := Authenticate(token)
	log.Println(res)
}
