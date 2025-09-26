package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	
	"fmt"
	"study/signature/aes_cbc/config"
)

var key = []byte(config.REQ_KEY)
var iv = []byte(config.REQ_IV)

func main(){
	//aes加密
	origin := `{"name":"ocean","age":18}`
	pwd, _ := Encrypt([]byte(origin))
	fmt.Println("pwd:", pwd)

	//解密
	res, err := Decrypt(pwd)
	fmt.Println(err)
	fmt.Println("res:", res)
}
func Decrypt(text string) (string,error){
	decode_data,err := base64.StdEncoding.DecodeString(text)
	if err != nil {
			return "",nil
	}
	//生成密码数据块cipher.Block
	block,_ := aes.NewCipher(key)
	//解密模式
	blockMode := cipher.NewCBCDecrypter(block,iv)
	//输出到[]byte数组
	origin_data := make([]byte,len(decode_data))
	blockMode.CryptBlocks(origin_data,decode_data)
	//去除填充,并返回
	return string(unpad(origin_data)),nil
}

func unpad(ciphertext []byte) []byte{
	length := len(ciphertext)
	//去掉最后一次的padding
	unpadding := int(ciphertext[length - 1])
	return ciphertext[:(length - unpadding)]
}
func Encrypt(text []byte) (string,error) {
	//生成cipher.Block 数据块
	block, err := aes.NewCipher(key)
	if err != nil {
			fmt.Println("错误 -" +err.Error())
			return "",err
	}
	//填充内容，如果不足16位字符
	blockSize := block.BlockSize()
	originData := pad(text,blockSize)
	//加密方式
	blockMode := cipher.NewCBCEncrypter(block,iv)
	//加密，输出到[]byte数组
	crypted := make([]byte,len(originData))
	blockMode.CryptBlocks(crypted,originData)
	return base64.StdEncoding.EncodeToString(crypted) , nil
}
func pad(ciphertext []byte, blockSize int) []byte{
	padding := blockSize - len(ciphertext) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)},padding)
	return append(ciphertext,padtext...)
}