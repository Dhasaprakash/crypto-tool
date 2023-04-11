package main

import "fmt"
import nexcrypto "crypto-tool/crypto"
import "crypto-tool/ioutil"
import "crypto/rsa"
import "crypto-tool/sign"

import (
	// "crypto"
	// "crypto/sha256"
	"bufio"
	"strconv"
	"strings"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
	"encoding/hex"
    "os")

func main() {

	var secretPlainText string
	var privateKeyAbsFileName string
	var privateKeyPEMPassPhrase string
	var pubKeyAbsFileName string
	var outFileNameWithAbsPath string
	var tenancy int
	
	fmt.Println("Enter 1 for Provider or 2 Consumer ")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\n", "", -1)
	tenancy, err := strconv.Atoi(text)
	if err != nil {
		panic(err)
	}
	
    if(tenancy == 1) {
		fmt.Println("Enter secret key ")
		secretPlainText, _ = reader.ReadString('\n')
		secretPlainText = strings.Replace(secretPlainText, "\n", "", -1)
		fmt.Println("Provider Private key filename with absolute path to sign")
		privateKeyAbsFileName, _ = reader.ReadString('\n')
		privateKeyAbsFileName = strings.Replace(privateKeyAbsFileName, "\n", "", -1)

		fmt.Println("Enter Private key pem passphrase")
		privateKeyPEMPassPhrase, _ = reader.ReadString('\n')
		privateKeyPEMPassPhrase = strings.Replace(privateKeyPEMPassPhrase, "\n", "", -1)

		fmt.Println("Consumer Public key filename with absolute path to encrypt the secret")
		pubKeyAbsFileName, _ = reader.ReadString('\n')
		pubKeyAbsFileName = strings.Replace(pubKeyAbsFileName, "\n", "", -1)
		
		fmt.Println("Enter out filename with absolute path")
		outFileNameWithAbsPath, _ = reader.ReadString('\n')
		outFileNameWithAbsPath = strings.Replace(outFileNameWithAbsPath, "\n", "", -1)
		privateKeyImported, err  := ioutil.ReadPrivateKeyPEMFile(privateKeyAbsFileName, privateKeyPEMPassPhrase)
		fmt.Println("values of input %s, %s, %s ", secretPlainText, privateKeyAbsFileName, pubKeyAbsFileName, outFileNameWithAbsPath, privateKeyImported)

		
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// fmt.Println("Private Key : ", privateKeyImported)

		publicKeyImported, err  := ioutil.ReadPublicKeyPEMFile(pubKeyAbsFileName)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// fmt.Println("public Key : ", publicKeyImported)
		hexString := nexcrypto.Encrypt(publicKeyImported, secretPlainText)
		ioutil.WriteFile(hexString, outFileNameWithAbsPath)
		sign.GenerateSignature(outFileNameWithAbsPath, privateKeyImported)
	} 
	
	if(tenancy == 2) {
		fmt.Println("Enter signature from Provider ")
		encodeSign, _ := reader.ReadString('\n')
		encodeSign = strings.Replace(encodeSign, "\n", "", -1)
		fmt.Println("Consumer Private key filename with absolute path to decrypt secret")
		privateKeyAbsFileName, _ = reader.ReadString('\n')
		privateKeyAbsFileName = strings.Replace(privateKeyAbsFileName, "\n", "", -1)

		fmt.Println("Enter Private key pem passphrase")
		privateKeyPEMPassPhrase, _ = reader.ReadString('\n')
		privateKeyPEMPassPhrase = strings.Replace(privateKeyPEMPassPhrase, "\n", "", -1)

		fmt.Println("Provider Public key filename with absolute path to verify sign")
		pubKeyAbsFileName, _ = reader.ReadString('\n')
		pubKeyAbsFileName = strings.Replace(pubKeyAbsFileName, "\n", "", -1)
		
		fmt.Println("Enter in filename with absolute path to verify and decrypt content")
		outFileNameWithAbsPath, _ = reader.ReadString('\n')
		outFileNameWithAbsPath = strings.Replace(outFileNameWithAbsPath, "\n", "", -1)
		privateKeyImported, err  := ioutil.ReadPrivateKeyPEMFile(privateKeyAbsFileName, privateKeyPEMPassPhrase)
		fmt.Println("values of input %s, %s, %s ", encodeSign, privateKeyAbsFileName, pubKeyAbsFileName, outFileNameWithAbsPath, privateKeyImported)
		publicKeyImported, err  := ioutil.ReadPublicKeyPEMFile(pubKeyAbsFileName)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		sign.VerifySignature(outFileNameWithAbsPath, publicKeyImported, encodeSign)
		var hexString string
		hexString, _ = ioutil.ReadFile(outFileNameWithAbsPath)
		
		fmt.Println("Encoded Hex String: ", hexString)

		decodedByteArray, err := hex.DecodeString(hexString)

		if err != nil {
			fmt.Println("Unable to convert hex to byte. ", err)
			panic(err)
		}
		
		fmt.Printf("Decoded Byte Array: %v ", decodedByteArray)

		decryptedMessage := nexcrypto.Decrypt(privateKeyImported, decodedByteArray)
		fmt.Println("decrypted message: ", decryptedMessage)
		
	}
}

func generateKeyPair() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey
	fmt.Println("Private key: %s Public Key %s ", privateKey, publicKey)
	
	
	// ExportPrivateKeyToPEM(&privateKey)
	// ReadPrivateKeyPEM()

}

// func ExportPrivateKeyToPEM(priv *crypto.PrivateKey) {
// 	pemPrivateFile, err := os.Create("priate_key.pem")
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	var pemPrivateBlock = &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(priv),
// 	}
// 	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// 	pemPrivateFile.Close()
// }

func ReadPrivateKeyPEM(privKeyFilePath string, privKeyPasspharse string) {
	privateKeyFile, err := os.Open(privKeyFilePath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	privateKeyFile.Close()
	var privPemBytes []byte
	data, _ := pem.Decode([]byte(pembytes))
	privPemBytes, err = x509.DecryptPEMBlock(data, []byte(privKeyPasspharse))
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(privPemBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Private Key : ", privateKeyImported)

	
}