package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var AppPath string
var keySource = flag.String("key", "", "your private key,require length more than 16")
var action = flag.String("a", "en", "action:en|de")
var fileIn = flag.String("in", "", "File with path to read")
var fileOut = flag.String("out", "", "File with path to create")

type AesEncrypt struct {
	Key []byte
}

func (self *AesEncrypt) Encode(source []byte) []byte {
	var iv = []byte(self.Key)[:aes.BlockSize]

	aesBlockEncrypter, err := aes.NewCipher(self.Key)
	if err != nil {
		panic(err)
	}
	encrypted := make([]byte, len(source))
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(encrypted, source)
	return encrypted
}

func (self *AesEncrypt) Decode(source []byte) []byte {
	var iv = []byte(self.Key)[:aes.BlockSize]
	decrypted := make([]byte, len(source))
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err := aes.NewCipher([]byte(self.Key))
	if err != nil {
		panic(err)
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(decrypted, source)
	return decrypted

}

func init() {
	AppPath, _ = os.Getwd()
	flag.Parse()
	if *keySource == "" {
		panic("You must set key!")
	}
	if len(*keySource) < 16 {
		panic("length must >16")
	}
	if *fileIn == "" {
		panic("file Input is null")
	}
	if *fileOut == "" {
		panic("file Output is null")
	}

}

func main() {

	key, err := hex.DecodeString(fmt.Sprintf("%x", *keySource))
	if err != nil {
		panic(err)
	}
	e := new(AesEncrypt)
	if len(key) > 32 {
		e.Key = key[:32]
	} else if len(key) > 24 {
		e.Key = key[:24]
	} else {
		e.Key = key[:16]
	}

	switch *action {
	case "en":
		inFile, err := os.OpenFile(AppPath+string(os.PathSeparator)+*fileIn, os.O_RDONLY, 0666)
		if err != nil {
			panic(err)
		}
		readByte, err := ioutil.ReadAll(inFile)
		if err != nil {
			panic(err)
		}
		result := e.Encode(readByte)

		outFile, err := os.OpenFile(AppPath+string(os.PathSeparator)+*fileOut, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			panic(err)
		}
		_, err = outFile.Write(result)
		if err != nil {
			panic(err)
		}
	case "de":

		inFile, err := os.OpenFile(AppPath+string(os.PathSeparator)+*fileIn, os.O_RDONLY, 0666)
		if err != nil {
			panic(err)
		}
		readByte, err := ioutil.ReadAll(inFile)
		if err != nil {
			panic(err)
		}
		result := e.Decode(readByte)

		outFile, err := os.OpenFile(AppPath+string(os.PathSeparator)+*fileOut, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			panic(err)
		}
		_, err = outFile.Write(result)
		if err != nil {
			panic(err)
		}

	}

}
