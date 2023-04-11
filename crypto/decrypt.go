package crypto
import "fmt"
import "crypto/rsa"
import (
	"crypto"
)
func Decrypt(privateKeyImported *rsa.PrivateKey, decodedByteArray []byte) string {
	decryptedBytes, err := privateKeyImported.Decrypt(nil, decodedByteArray, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	decryptedString := string(decryptedBytes)
	fmt.Println("decrypted message: ",decryptedString)
	return decryptedString
}