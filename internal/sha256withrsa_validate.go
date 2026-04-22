package internal

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// SHA256WithRSAValidate validate Sha256 with RSA Public key
func SHA256WithRSAValidate(publicKey, input, signature string) error {
	var err error
	var rawSignature []byte
	var block *pem.Block
	var pub any

	rawSignature, err = base64.StdEncoding.DecodeString(signature)

	if err == nil {
		block, _ = pem.Decode([]byte(publicKey))
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	}

	if err == nil {
		hashed := sha256.Sum256([]byte(input))
		pubKey, ok := pub.(*rsa.PublicKey)
		err = errors.New("invalid rsa public key")
		if ok {
			err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], rawSignature)
		}
	}

	return err
}
