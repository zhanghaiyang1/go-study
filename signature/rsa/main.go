package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	keySize          = 1024
	maxEncryptBlock  = 117 // 1024位密钥，PKCS#1 v1.5 填充后最大明文长度
	maxDecryptBlock  = 128 // 密文固定为 128 字节
	encoding         = "UTF-8"
)

// 清理 Base64 字符串中的非法字符（空格、换行等）
func cleanBase64(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			return r
		}
		return -1
	}, s)
}

// 解析 PKCS#8 格式私钥（Base64 字符串 → *rsa.PrivateKey）
func parsePrivateKey(base64Key string) (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(cleanBase64(base64Key))
	if err != nil {
		return nil, fmt.Errorf("base64 decode private key failed: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// 尝试 PEM 格式（部分密钥可能带 -----BEGIN... 头）
		block, _ := pem.Decode(der)
		if block != nil {
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key failed: %w", err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

// 解析 X.509 格式公钥（Base64 字符串 → *rsa.PublicKey）
func parsePublicKey(base64Key string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(cleanBase64(base64Key))
	if err != nil {
		return nil, fmt.Errorf("base64 decode public key failed: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		// 尝试 PEM 格式
		block, _ := pem.Decode(der)
		if block != nil {
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parse X.509 public key failed: %w", err)
		}
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaKey, nil
}

// RSA 公钥加密（支持分段）
func RSAEncrypt(plaintext, publicKeyBase64 string) (string, error) {
	pubKey, err := parsePublicKey(publicKeyBase64)
	if err != nil {
		return "", err
	}

	data := []byte(plaintext)
	var chunks [][]byte
	for len(data) > 0 {
		chunkSize := maxEncryptBlock
		if len(data) < chunkSize {
			chunkSize = len(data)
		}
		chunks = append(chunks, data[:chunkSize])
		data = data[chunkSize:]
	}

	var encryptedChunks [][]byte
	for _, chunk := range chunks {
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, chunk)
		if err != nil {
			return "", fmt.Errorf("encrypt chunk failed: %w", err)
		}
		encryptedChunks = append(encryptedChunks, encrypted)
	}

	// 合并密文并 Base64 编码
	combined := []byte{}
	for _, chunk := range encryptedChunks {
		combined = append(combined, chunk...)
	}
	return base64.StdEncoding.EncodeToString(combined), nil
}

// RSA 私钥解密（支持分段）
func RSADecrypt(base64Ciphertext, privateKeyBase64 string) (string, error) {
	privKey, err := parsePrivateKey(privateKeyBase64)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cleanBase64(base64Ciphertext))
	if err != nil {
		return "", fmt.Errorf("base64 decode ciphertext failed: %w", err)
	}

	var chunks [][]byte
	for len(ciphertext) > 0 {
		chunkSize := maxDecryptBlock
		if len(ciphertext) < chunkSize {
			chunkSize = len(ciphertext)
		}
		chunks = append(chunks, ciphertext[:chunkSize])
		ciphertext = ciphertext[chunkSize:]
	}

	var decryptedChunks [][]byte
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, chunk)
		if err != nil {
			return "", fmt.Errorf("decrypt chunk failed: %w", err)
		}
		decryptedChunks = append(decryptedChunks, decrypted)
	}

	// 合并明文
	combined := []byte{}
	for _, chunk := range decryptedChunks {
		combined = append(combined, chunk...)
	}
	return string(combined), nil
}

// ============ 测试代码 ============
var (
	RSAprivateKey = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM2VGsDYC4h8ZZQMffETP4iDtPEgRduLOoyeD+YUY0PnYxD792Hx9T7gEm1AVg1x+QK5jQH4cXy/3XkEf7Nd5RWridju1y4mMDPGdFiSVWXtcucc9KsSPg0hbMq3dTY+KGRk1YfwaH5UUteh4kJaFaIqJM58qj7IvFP4O1p9rMcdAgMBAAECgYEAt4lPai03FrHgSe1hHrHNfcX/62mhlGBXdCTFEubOvFe+VPJuKA5IocqQCONwL+65ndoj7kdsoi/0vM7sZykDk9unHOwlRGhqVV3sGB9SkIfYuRU/6DDi7jq5fmNE2H6B7yHOX/Tp0fW70ZP//5R0eErl5NqEl6vP4HhOa9l8Na0CQQD0vXIZIco46oXgOcTTbaNWyFxY0f8XS62D7yvxHqmNK1o8q6Fpt+uFgsCJ7Qetfvh+7MKT9Pz/PgqflWGuZqlHAkEA1wp1tKSSwhIXB7vLpNnogz4g+lwY0JMtca08tca0gqI1QpJDcfSp9uNYT0TnES/5LUkV3HoTFjNJYEirmPP+ewJAeg7lka0terdUL2EATeX3OXfRvqZ0z3x5vDwTMTz2mKZPacS7SstkVgDA38jsNFYHvt17qWjcqLubdr18qwseTwJAQ/hnahjW1ob3RpeCb/H8v3ck31267jqHE7ZpSR+ssNnqsccfkGaATqxfnnat/s3GGh1Ozqi7XboKSGfP7YG5/wJAMPcD9PZf5o2T59gyBb2T0WZoaU7CNoZImfH8QkznB1a+FpKHzwOqmRGHzecbFYJguD3AYq19vNNHsNdrdDrYLQ==`
	RSApublicKey  = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNlRrA2AuIfGWUDH3xEz+Ig7TxIEXbizqMng/mFGND52MQ+/dh8fU+4BJtQFYNcfkCuY0B+HF8v915BH+zXeUVq4nY7tcuJjAzxnRYklVl7XLnHPSrEj4NIWzKt3U2PihkZNWH8Gh+VFLXoeJCWhWiKiTOfKo+yLxT+DtafazHHQIDAQAB`
	message       = `{"publicOrderVo":{"policyDynamicVos":[{"dynamicValue":"开","dynamicId":"1","dynamicMean":"旅行1目的地 ","insuredNo":"1","itemNo":"1","dynamicKey":"travleDes"}],"policyProgrammeVos":[{"policyRdrCategoryVos":[{"itemNo":"1","personDecimal":"1","plan":"01MD0001"}]}],"policyMainVo":{"amount":"145000","effectiveTm":"2021-07-31 00:00:00","premium":"45","productCode":"01MD","chlCode":"HT100042","proTm":"2021-07-30 15:18:28","terminalTm":"2021-09-29 00:00:00","paymentWayCode":"1","copy":"1","dataProducer":"PB"},"policyInsuredVos":[{"insuredNum":"11010119990101023X","insuredGender":"1","insuredTelNum":"15001132199","islegal":"1","isHolder":"0","insuredIdType":"01","insuredNo":"1","insuredType":"1","itemNo":"1","insuredBirthday":"1999-01-01","insuredName":"核酸 ","relationship":"03"}],"policyApplicantVo":{"appEmail":"11111@qq.com","appNum":"110101199901010096","apptelNum":"15001132199","appGender":"1","appName":"验证 ","appType":"1","appidType":"01","visaType":"2","appBirthday":"1999-01-01 00:00:00"}},"requestHeadVo":{"requestType":"HTIC002","channelCode":"HT100042"}}`
)

func main() {
	// 测试加密
	encrypted, err := RSAEncrypt(message, RSApublicKey)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}
	fmt.Println("Encrypted (Base64):")
	fmt.Println(encrypted)

	// 测试解密
	decrypted, err := RSADecrypt(encrypted, RSAprivateKey)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}
	fmt.Println("\nDecrypted:")
	fmt.Println(decrypted)

	// 验证一致性
	if decrypted == message {
		fmt.Println("\n✓ Decryption successful: original message recovered")
	} else {
		fmt.Println("\n✗ Decryption failed: message mismatch")
	}
}