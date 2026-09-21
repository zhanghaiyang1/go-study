package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

// JDAZAes 工具类
type JDAZAes struct{}

// getRawKey 严格匹配 Java KeyGenerator.getInstance("AES") + SHA1PRNG 的实现
// 逻辑：SHA1(SHA1(seed)) 取前 16 字节
func (j *JDAZAes) getRawKey(seed []byte) []byte {
	h := sha1.New()
	h.Write(seed)
	firstHash := h.Sum(nil)

	h2 := sha1.New()
	h2.Write(firstHash)
	secondHash := h2.Sum(nil)

	return secondHash[:16]
}

// Des3EncodeCbc 生成 seed (3DES CBC)
func (j *JDAZAes) Des3EncodeCbc(userCode, publicKey string) (string, error) {
	iv := []byte{2, 3, 4, 5, 6, 7, 8, 9}
	keyRaw := userCode + publicKey

	// Java StringUtils.leftPad 逻辑
	if len(keyRaw) < 24 {
		fillChar := publicKey[:1]
		keyRaw = strings.Repeat(fillChar, 24-len(keyRaw)) + keyRaw
	}
	keyBytes := []byte(keyRaw)[:24]

	block, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return "", err
	}

	plainData := []byte(userCode)
	paddedData := pkcs5Padding(plainData, block.BlockSize())
	
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(paddedData))
	blockMode.CryptBlocks(cipherText, paddedData)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// EncryptBase64 AES ECB 加密
func (j *JDAZAes) EncryptBase64(seed, content string) (string, error) {
	key := j.getRawKey([]byte(seed))
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainText := []byte(content)
	paddedText := pkcs5Padding(plainText, block.BlockSize())
	
	// AES ECB 模式加密 (Java 默认)
	cipherText := make([]byte, len(paddedText))
	for bs, be := 0, block.BlockSize(); bs < len(paddedText); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(cipherText[bs:be], paddedText[bs:be])
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// PKCS5 填充
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func main() {
	price := int64(1119)

	invoiceAmount, _ := decimal.NewFromInt(price).Div(decimal.NewFromInt(100)).Float64()
	fmt.Println("InvoiceAmount:", invoiceAmount)
	// 预期: 11.19
	userCode := "AC600001_01"
	publicKey := "bc0TYXab4UjcZiOtX9XpdQ"
	plainText := "AAA加密前的明文内容BBB"

	utils := &JDAZAes{}

	// 1. 生成 Seed
	seed, _ := utils.Des3EncodeCbc(userCode, publicKey)
	fmt.Println("Seed:", seed) 
	// 预期: 9yMoKeEB+W2jIf2T0Z7qXg==

	// 2. 加密
	cipherText, _ := utils.EncryptBase64(seed, plainText)
	fmt.Println("CipherText:", cipherText)
	// 预期: N0Cfs3ta2/tG7kLJE/Ev8KQfJwqNnIk9X5+JTL1rOMU=
}