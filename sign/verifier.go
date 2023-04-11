package sign


import "fmt"
import "crypto/rsa"
import (
	"io"
	"os"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
)

func VerifySignature(fileToVerifySign string, publicKey *rsa.PublicKey, encodedSignature string) {
	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	file, err := os.Open(fileToVerifySign); 
	if err != nil {
		panic(err)
	}
	msgHash := sha256.New()
	if _, err = io.Copy(msgHash, file); err != nil {
		panic(err)
	  }
	// _, err := msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)
	signature, err := hex.DecodeString(encodedSignature)
	if err != nil {
		fmt.Println("Unable to convert hex to byte. ", err)
		panic(err)
	}
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		panic(err)
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")
}