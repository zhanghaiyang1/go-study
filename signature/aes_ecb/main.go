package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
)

const (
	keyAES             = "AES"
	algorithmModePadding = "AES/ECB/PKCS5Padding"
)

func main() {
	// Example usage
	key := "57be704d01c44070b18ac11333ea1381"
	// plaintext := `{"policyCorrect":{"id":1895384235495591938,"correctNo":"3097922190231510002","policyNo":"10203113900181669410","correctType":4,"effectiveDate":"2025-03-01 00:00:00","correctDate":"2025-02-28","correctPremiumInCents":0,"correctPremiumInCentsNoTax":0,"correctClauseList":[{"prodNo":"171564","correctPremiumInCents":0,"correctPremiumInCentsNoTax":0}],"invoices":null,"elePolicys":["https://baoying-dev.oss-cn-beijing.aliyuncs.com/1740729789104deZkh/%E5%B9%B3%E5%AE%89%E9%93%B6%E8%A1%8C%E5%8D%A1%E7%9B%97%E5%88%B7%E4%BF%9D%E9%99%A9%E6%9D%A1%E6%AC%BE.pdf?Expires=1740733889&OSSAccessKeyId=LTAI4Fxw5RjtxmXhpPXPyVdv&Signature=BbMLCh%2B0duZ%2Ftj5zgob78nb7%2FE0%3D"],"payUrl":null,"sub":"250221174013133273","status":2,"employeeInfos":null,"insurantList":[{"name":"刘世界","idType":1,"idNo":"340501201401011716","mobile":null,"birth":"2014-01-01","sex":1,"address":null,"occupation":"机关内勤","contractName":null,"email":null,"relation":null,"isHighWork":false,"jobCode":"N010101","profession":null,"insurantType":3,"replaceName":"刘事儿","replaceIdentityType":1,"replaceIdentity":"330101200001011217","replaceJobCode":null,"replaceProfession":null,"jobRootCode":"N0","jobType":1}],"correctOrderNo":"B26510020250228000001","paymentMode":null},"invoice":{"invoiceHeadType":3,"invoiceType":null,"taxpayerName":null,"taxpayerNo":null,"companyTel":null,"email":null,"bank":null,"bankNo":null,"registerAddress":null,"addresseeName":null,"addressee":null,"addresseeTel":null,"status":1,"premium":null}}`

	// // Encrypt
	// encrypted, err := Encrypt(plaintext, key)
	// if err != nil {
	// 	log.Fatal("Encryption failed:", err)
	// }
	// log.Println("Encrypted text:", encrypted)

	encrypted := "TgDvt8LO1/Y2ozlLPnF1hM1TwblgYHVmv3jObDgbjIrXxyXznqN1M9+1Fnzavnf5cDR03csP2VldMXhr0M0A/hAM79BxcEfT5zhX6p06MmBvi/ULRk7SZmX1phnSbxSLtWEBJmV6OQt9FSDfo1TGBxOj20fNwmAjNaTADfVwK14DmDjAMw7ObHImrQJbQeX+LoJN63J/+vE7x4xzMSwxnDaJ/QLOBsjy4UyJf15ldcA="
	// Decrypt
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		log.Fatal("Decryption failed:", err)
	}
	log.Println("Decrypted text:", decrypted)
}

// Encrypt encrypts the given plaintext using the provided key.
func Encrypt(plaintext, key string) (string, error) {
	if key == "" {
		return "", errors.New("key is empty")
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println("AES cipher creation error:", err)
		return "", err
	}

	// Pad the plaintext to match the block size
	plaintextBytes := []byte(plaintext)
	plaintextBytes = pkcs5Pad(plaintextBytes, block.BlockSize())

	// ECB mode does not require an IV, so we can directly use the block
	mode := newECBEncrypter(block)
	ciphertext := make([]byte, len(plaintextBytes))
	mode.CryptBlocks(ciphertext, plaintextBytes)

	// Encode the ciphertext in base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given encrypted string using the provided key.
func Decrypt(sSrc, sKey string) (string, error) {
	if sKey == "" {
		return "", errors.New("key is empty")
	}

	// Decode the base64 encoded source string
	encrypted, err := base64.StdEncoding.DecodeString(sSrc)
	if err != nil {
		log.Println("Base64 decode error:", err)
		return "", err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher([]byte(sKey))
	if err != nil {
		log.Println("AES cipher creation error:", err)
		return "", err
	}

	// ECB mode does not require an IV, so we can directly use the block
	mode := newECBDecrypter(block)
	plaintext := make([]byte, len(encrypted))
	mode.CryptBlocks(plaintext, encrypted)

	// Unpad the plaintext
	plaintext, err = pkcs5Unpad(plaintext, block.BlockSize())
	if err != nil {
		log.Println("Unpadding error:", err)
		return "", err
	}

	return string(plaintext), nil
}

// pkcs5Pad adds PKCS5 padding to the plaintext.
func pkcs5Pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// pkcs5Unpad removes PKCS5 padding from the plaintext.
func pkcs5Unpad(plaintext []byte, blockSize int) ([]byte, error) {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return plaintext[:(length - unpadding)], nil
}

// ecbEncrypter represents an ECB mode encrypter.
type ecbEncrypter struct {
	b         cipher.Block
	blockSize int
}

func newECBEncrypter(b cipher.Block) *ecbEncrypter {
	return &ecbEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// ecbDecrypter represents an ECB mode decrypter.
type ecbDecrypter struct {
	b         cipher.Block
	blockSize int
}

func newECBDecrypter(b cipher.Block) *ecbDecrypter {
	return &ecbDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}