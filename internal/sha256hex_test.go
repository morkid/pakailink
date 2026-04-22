package internal

import (
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	input := "hello world"
	output := SHA256Hex(input)

	if output != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Error("encryption failed")
		t.FailNow()
	}
}
