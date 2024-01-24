package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestSprintf(t *testing.T) {
	start := time.Now()
	str := fmt.Sprintf("helo %v", "bye")

	fmt.Println("time took to concat string with sprinf", time.Since(start))
	_ = str
}

func TestString(t *testing.T) {
	start := time.Now()
	str := "helo" + "bye"

	fmt.Println("time took to concat string with operator", time.Since(start))
	_ = str
}
