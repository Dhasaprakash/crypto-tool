package sign

import "fmt"
import "crypto/rsa"
import (
	"io"
	"os"
	"encoding/hex"
	"crypto"
	"crypto/sha256"
    "crypto/rand"
	
)

func GenerateSignature(fileToGenerateSign string, privateKey *rsa.PrivateKey) {
	// msg := []byte("verifiable message")

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	file, err := os.Open(fileToGenerateSign); 
	if err != nil {
		panic(err)
	}
	msgHash := sha256.New()
	if _, err := io.Copy(msgHash, file); err != nil {
		panic(err)
	  }
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	fmt.Println("Hash vale to sign ", msgHashSum)
	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("File signature ", hex.EncodeToString(signature))
}