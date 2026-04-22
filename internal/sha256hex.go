package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func SHA256Hex(input string) string {
	dataBytes := []byte(input)
	hashBytes := sha256.Sum256(dataBytes)

	return strings.ToLower(hex.EncodeToString(hashBytes[:]))
}
