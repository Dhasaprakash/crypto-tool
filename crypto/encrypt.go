package crypto

import "fmt"
import "crypto/rsa"
import (
	"crypto/sha256"
    "crypto/rand"
	"encoding/hex"
)

func Encrypt(publicKeyImported *rsa.PublicKey, secret string) string {
	fmt.Println("Encrypt ")
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKeyImported,
		[]byte(secret),
		nil)
	if err != nil {
		panic(err)
	}
	
	fmt.Println("encrypted bytes: ", encryptedBytes)
	hexString := hex.EncodeToString(encryptedBytes)

	fmt.Println("Encoded Hex String: ", hexString)
	return hexString
}