package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

var blockTypes = map[string]func([]byte) (any, error){
	"RSA PRIVATE KEY": func(b []byte) (any, error) {
		return x509.ParsePKCS1PrivateKey(b)
	},
	"PRIVATE KEY": x509.ParsePKCS8PrivateKey,
}

func SHA256WithRSA(privateKey, input string) (output string, err error) {
	var key *rsa.PrivateKey
	var block *pem.Block
	var parsedKey any
	block, _ = pem.Decode([]byte(privateKey))
	blockFunc, ok := blockTypes[block.Type]
	err = errors.New("unsupported key type")

	if ok {
		parsedKey, err = blockFunc(block.Bytes)
	}

	if err == nil {
		var ok bool
		err = errors.New("invalid rsa key")
		key, ok = parsedKey.(*rsa.PrivateKey)
		if ok {
			err = nil
		}
	}

	if err == nil {
		hashed := sha256.Sum256([]byte(input))
		var signature []byte
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
		if err == nil {
			output = base64.StdEncoding.EncodeToString(signature)
		}
	}

	return
}
