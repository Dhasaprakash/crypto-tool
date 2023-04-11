package ioutil

import "io/ioutil"
import "fmt"
import "os"
import "crypto/rsa"
import (
    "crypto/x509"
    "encoding/pem"
    )

func ReadFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	var enc_secret string
	if (err == nil) {
		enc_secret = string(data)
		// fmt.Println("data ",enc_secret)
	}

	return enc_secret, err
}

func WriteFile(content string, filename string)  (error) {
	err := ioutil.WriteFile(filename, []byte(content), os.ModePerm)
	if(err != nil) {
		fmt.Println("Error in creating file %s, error %v ", filename, err)
		return err
	}
	fmt.Println("creating new file %s", filename)
	return nil
}

func ReadPrivateKeyPEMFile(rsaPrivateKeyLocation, privatePassphrase string) (*rsa.PrivateKey, error) {
    if rsaPrivateKeyLocation == "" {
        fmt.Println("No RSA Key given, generating temp one")
    }

    priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
    if err != nil {
        fmt.Println("No RSA private key found, generating temp one")
    }

    privPem, _ := pem.Decode(priv)

    if privPem.Type != "RSA PRIVATE KEY" {
        fmt.Println("RSA private key is of the wrong type", privPem.Type)
    }

    if x509.IsEncryptedPEMBlock(privPem) && privatePassphrase == "" {
        fmt.Println("Passphrase is required to open private pem file")
    }

    var privPemBytes []byte

    if privatePassphrase != "" {
        privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(privatePassphrase))
    } else {
        privPemBytes = privPem.Bytes
    }

    var parsedKey interface{}
    //PKCS1
    if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
        //If what you are sitting on is a PKCS#8 encoded key
        if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
            fmt.Println("Unable to parse RSA private key, generating a temp one", err)
        }
    }

    var privateKey *rsa.PrivateKey
    var ok bool
    privateKey, ok = parsedKey.(*rsa.PrivateKey)
    if !ok {
        fmt.Println("Unable to parse RSA private key, generating a temp one", err)
        
    }

    return privateKey, nil
}

func ReadPublicKeyPEMFile(rsaPublicKeyLocation string) (*rsa.PublicKey, error){
	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
    if err != nil {
        fmt.Println("No RSA public key found, generating temp one")
    }
    pubPem, _ := pem.Decode(pub)
    if pubPem == nil {
        fmt.Println("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key - rsa public key not in pem format")
    }
	var parsedKey interface{}
	var ok bool
    if pubPem.Type != "RSA PUBLIC KEY" {
        fmt.Println("RSA public key is of the wrong type", pubPem.Type)
    }

    if parsedKey, err = x509.ParsePKCS1PublicKey(pubPem.Bytes); err != nil {
        fmt.Println("Unable to parse RSA public key, generating a temp one", err)
    }

    var pubKey *rsa.PublicKey
    if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
        fmt.Println("Unable to parse RSA public key, generating a temp one", err)
    }

    return pubKey, nil
}