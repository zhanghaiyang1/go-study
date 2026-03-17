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

	fmt.Printf("Ciphertext : %s \n", ciphertext)
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
	RSAprivateKey = `MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALydbL8cl56tXpzFrBP0HzSCV4xTsGYdnk1Q/iUNEz5nyxcKpwxkj7D2Orz5TOzKyS0H7nHeHXg7ekkV4IhLm6nuMqIL9tssmnTJt/f0DMDnprbf0VfHGsY/tQEV5yNoxdBR0d44ojW7ztlJhRE8ioNXc7poKvLSHg/FjN0Q2vE5AgMBAAECgYEAqN28xeHgcUVA5tUnefnfklB793vZ+6La3tf7ocpyBzZAItH7u2GxMDtTXWtKDtqDgNiQB8xX0BRYKGT40K34n4LRGGzFMWB2JaXaXSBB8cZGejVfXQWwU3IFphYLCwq1QECVDwuS24QKe6t+O9QegmwUxVgxb+LY54fGHqMPTS0CQQDd7BKd4JdZaViO1OpDVtF6ScPaLW5fb0yB99KvxizhRwff2IzWl2LZ/OeVrSDIHiy4TcGA+GoyzNXlLArho/EDAkEA2ZQFLONBmw8xE5bU6EKjVu+i3GlhUWCuBYyp/dAV3Ha2KjbJJAJjwI1WRAqobtQNuwS4SXiPS+fy/w5c0qdaEwJAJogdt2HOhYy//pTDVAvX9UanhdNLjbBydUKFR1W+ZyMBIAGmen/wfu7letyDi5uJojqF9ZGsRsPAA7mA7iqb5wJBAK52WCgEGakB53IzsYiDVoHxKP/fp98ezKs6fVw9rCnZLnxu7Z3oJKBTNGbevOwRMOlTAYo4F37gACKwG5H2Cu0CQBJffMwwRi+hJvxdGUtPa/+k/VF9JUTxsfE/mokaEd5nKEQjMRCJY7XnM/FmTMmSLIOFUrvOUOC4CW+Q6a9LXc0=`
	RSApublicKey  = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8nWy/HJeerV6cxawT9B80gleMU7BmHZ5NUP4lDRM+Z8sXCqcMZI+w9jq8+UzsysktB+5x3h14O3pJFeCIS5up7jKiC/bbLJp0ybf39AzA56a239FXxxrGP7UBFecjaMXQUdHeOKI1u87ZSYURPIqDV3O6aCry0h4PxYzdENrxOQIDAQAB`
	message       = `{"publicOrderVo":{"policyApplicantVo":{"appAddr":"广西壮族自治区南宁市江南区南宁市江南区五一西路沙井大道交汇东侧（南宁市绍毅停车场有限责任公司）D区109、110、111号铺面","appBirthday":"","appContact":"","appEmail":"13427079@qq.com","appGender":"1","appName":"广西城达商贸有限公司","appNum":"91450100MABM9LX97F","appType":"2","appidType":"97","apptelNum":""},"policyBeneficiaryVos":[],"policyDynamicVos":[{"dynamicId":"1","dynamicKey":"feeRatio","dynamicMean":"手续费","dynamicValue":"45","itemNo":1}],"policyInsuredVos":[{"creditLevel":"HT3001249","insuredBirthday":783964800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试1","insuredNo":1,"insuredNum":"452127199411051518","insuredTelNum":"18615004665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":649954800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试2","insuredNo":2,"insuredNum":"452122199008073619","insuredTelNum":"18665304665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":589474800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试3","insuredNo":3,"insuredNum":"450923198809064038","insuredTelNum":"18665104665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":591724800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试4","insuredNo":4,"insuredNum":"450923198810023073","insuredTelNum":"18665004265","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":224265600000,"insuredGender":"2","insuredIdType":"01","insuredName":"测试5","insuredNo":5,"insuredNum":"452802197702093920","insuredTelNum":"18665001665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"}],"policyMainVo":{"chlCode":"HT1604763","chlName":"山西","chlOrderNo":"wrqwrqwr","copy":1,"effectiveTm":"2026-01-20 00:00:00","paymentWayCode":"1","premium":2527.06,"proTm":"2026-01-13 09:32:00","productCode":"09H0","productName":"华泰团体意外险","terminalTm":"2027-01-19 23:59:59"},"policyProgrammeVos":[{"gasPeriod":0,"policyRdrCategoryVos":[{"itemNo":1,"personDecimal":"5","plan":"09H00001"}],"policyRdrVos":[{"itemNo":1,"plan":"09H00001","rdrAmount":"200000","rdrCode":"4029561","rdrName":"意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"2001952","rdrName":"意外伤害医疗","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029323","rdrName":"附加意外伤害医疗(A款)","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029324","rdrName":"附加意外伤害医疗(B款)","rdrRemark":"含社保外医疗费用，每次事故免赔100元，赔付比例80%","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029342","rdrName":"附加意外伤害住院津贴(A款)","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029220","rdrName":"特定传染病身故保险金（A）","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4028895","rdrName":"附加救护车费用保险","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4028720","rdrName":"附加猝死保险","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4001029","rdrName":"火车轮船轨道交通意外身故伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000016","rdrName":"民航班机意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000019","rdrName":"营运汽车意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000022","rdrName":"非营运汽车意外身故/伤残","rdrRemark":"","sort":0}]}]},"requestHeadVo":{"caller":"M","channelCode":"HT1604763","requestType":"HTIC001"}}`
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