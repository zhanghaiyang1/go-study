package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"fmt"
	"log"
	"strings"
)

// 定义常量
const (
	MaxEncryptBlock = 117 // RSA 最大加密明文大小 (1024 bit key - 11 padding)
	MaxDecryptBlock = 128 // RSA 最大解密密文大小 (1024 bit key / 8)
)

// 预定义的密钥 (直接从 Java 代码复制)
const RSAPrivateKey = `MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALydbL8cl56tXpzFrBP0HzSCV4xTsGYdnk1Q/iUNEz5nyxcKpwxkj7D2Orz5TOzKyS0H7nHeHXg7ekkV4IhLm6nuMqIL9tssmnTJt/f0DMDnprbf0VfHGsY/tQEV5yNoxdBR0d44ojW7ztlJhRE8ioNXc7poKvLSHg/FjN0Q2vE5AgMBAAECgYEAqN28xeHgcUVA5tUnefnfklB793vZ+6La3tf7ocpyBzZAItH7u2GxMDtTXWtKDtqDgNiQB8xX0BRYKGT40K34n4LRGGzFMWB2JaXaXSBB8cZGejVfXQWwU3IFphYLCwq1QECVDwuS24QKe6t+O9QegmwUxVgxb+LY54fGHqMPTS0CQQDd7BKd4JdZaViO1OpDVtF6ScPaLW5fb0yB99KvxizhRwff2IzWl2LZ/OeVrSDIHiy4TcGA+GoyzNXlLArho/EDAkEA2ZQFLONBmw8xE5bU6EKjVu+i3GlhUWCuBYyp/dAV3Ha2KjbJJAJjwI1WRAqobtQNuwS4SXiPS+fy/w5c0qdaEwJAJogdt2HOhYy//pTDVAvX9UanhdNLjbBydUKFR1W+ZyMBIAGmen/wfu7letyDi5uJojqF9ZGsRsPAA7mA7iqb5wJBAK52WCgEGakB53IzsYiDVoHxKP/fp98ezKs6fVw9rCnZLnxu7Z3oJKBTNGbevOwRMOlTAYo4F37gACKwG5H2Cu0CQBJffMwwRi+hJvxdGUtPa/+k/VF9JUTxsfE/mokaEd5nKEQjMRCJY7XnM/FmTMmSLIOFUrvOUOC4CW+Q6a9LXc0=`

const RSAPublicKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8nWy/HJeerV6cxawT9B80gleMU7BmHZ5NUP4lDRM+Z8sXCqcMZI+w9jq8+UzsysktB+5x3h14O3pJFeCIS5up7jKiC/bbLJp0ybf39AzA56a239FXxxrGP7UBFecjaMXQUdHeOKI1u87ZSYURPIqDV3O6aCry0h4PxYzdENrxOQIDAQAB`

// const RSAPrivateKey = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM2VGsDYC4h8ZZQMffETP4iDtPEgRd uLOoyeD+YUY0PnYxD792Hx9T7gEm1AVg1x+QK5jQH4cXy/3XkEf7Nd5RWridju1y4mMDPGdFiSVWXtcu cc9KsSPg0hbMq3dTY+KGRk1YfwaH5UUteh4kJaFaIqJM58qj7IvFP4O1p9rMcdAgMBAAECgYEAt4lPai 03FrHgSe1hHrHNfcX/62mhlGBXdCTFEubOvFe+VPJuKA5IocqQCONwL+65ndoj7kdsoi/0vM7sZykDk9 unHOwlRGhqVV3sGB9SkIfYuRU/6DDi7jq5fmNE2H6B7yHOX/Tp0fW70ZP//5R0eErl5NqEl6vP4HhOa9 l8Na0CQQD0vXIZIco46oXgOcTTbaNWyFxY0f8XS62D7yvxHqmNK1o8q6Fpt+uFgsCJ7Qetfvh+7MKT9P z/PgqflWGuZqlHAkEA1wp1tKSSwhIXB7vLpNnogz4g+lwY0JMtca08tca0gqI1QpJDcfSp9uNYT0TnES /5LUkV3HoTFjNJYEirmPP+ewJAeg7lka0terdUL2EATeX3OXfRvqZ0z3x5vDwTMTz2mKZPacS7SstkVg DA38jsNFYHvt17qWjcqLubdr18qwseTwJAQ/hnahjW1ob3RpeCb/H8v3ck31267jqHE7ZpSR+ssNnqsc cfkGaATqxfnnat/s3GGh1Ozqi7XboKSGfP7YG5/wJAMPcD9PZf5o2T59gyBb2T0WZoaU7CNoZImfH8Qk znB1a+FpKHzwOqmRGHzecbFYJguD3AYq19vNNHsNdrdDrYLQ==`
// const RSAPublicKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNlRrA2AuIfGWUDH3xEz+Ig7TxIEXbizqMng/mFG ND52MQ+/dh8fU+4BJtQFYNcfkCuY0B+HF8v915BH+zXeUVq4nY7tcuJjAzxnRYklVl7XLnHPSrEj4NIW zKt3U2PihkZNWH8Gh+VFLXoeJCWhWiKiTOfKo+yLxT+DtafazHHQIDAQAB`
// 示例消息 (从 Java 代码复制，去除了换行符以使其成为合法的 JSON 字符串)
// 注意：原 Java 代码中的 message 字符串包含了很多换行和空格，实际解析前通常需要清理或保持原样。
// 这里为了演示，我们使用一个清理过的版本，或者直接使用原字符串（如果 JSON 解析器能处理空白符）。
// 原 Java 代码先 parseObject 再 toJSONString，这通常会压缩掉多余的空白。
const OriginalMessage = `{"publicOrderVo":{"policyApplicantVo":{"appAddr":"广西壮族自治区南宁市江南区南宁市江南区五一西路沙井大道交汇东侧（南宁市绍毅停车场有限责任公司）D区109、110、111号铺面","appBirthday":"","appContact":"","appEmail":"13427079@qq.com","appGender":"1","appName":"广西城达商贸有限公司","appNum":"91450100MABM9LX97F","appType":"2","appidType":"97","apptelNum":""},"policyBeneficiaryVos":[],"policyDynamicVos":[{"dynamicId":"1","dynamicKey":"feeRatio","dynamicMean":"手续费","dynamicValue":"45","itemNo":1}],"policyInsuredVos":[{"creditLevel":"HT3001249","insuredBirthday":783964800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试1","insuredNo":1,"insuredNum":"452127199411051518","insuredTelNum":"18615004665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":649954800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试2","insuredNo":2,"insuredNum":"452122199008073619","insuredTelNum":"18665304665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":589474800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试3","insuredNo":3,"insuredNum":"450923198809064038","insuredTelNum":"18665104665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":591724800000,"insuredGender":"1","insuredIdType":"01","insuredName":"测试4","insuredNo":4,"insuredNum":"450923198810023073","insuredTelNum":"18665004265","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"},{"creditLevel":"HT3001249","insuredBirthday":224265600000,"insuredGender":"2","insuredIdType":"01","insuredName":"测试5","insuredNo":5,"insuredNum":"452802197702093920","insuredTelNum":"18665001665","insuredType":"1","isHolder":"0","islegal":"1","itemNo":1,"occupationCodeName":"销售人员","relationship":"05"}],"policyMainVo":{"chlCode":"HT1604763","chlName":"山西","chlOrderNo":"wrqwrqwr","copy":1,"effectiveTm":"2026-01-20 00:00:00","paymentWayCode":"1","premium":2527.06,"proTm":"2026-01-13 09:32:00","productCode":"09H0","productName":"华泰团体意外险","terminalTm":"2027-01-19 23:59:59"},"policyProgrammeVos":[{"gasPeriod":0,"policyRdrCategoryVos":[{"itemNo":1,"personDecimal":"5","plan":"09H00001"}],"policyRdrVos":[{"itemNo":1,"plan":"09H00001","rdrAmount":"200000","rdrCode":"4029561","rdrName":"意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"2001952","rdrName":"意外伤害医疗","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029323","rdrName":"附加意外伤害医疗(A款)","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029324","rdrName":"附加意外伤害医疗(B款)","rdrRemark":"含社保外医疗费用，每次事故免赔100元，赔付比例80%","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029342","rdrName":"附加意外伤害住院津贴(A款)","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4029220","rdrName":"特定传染病身故保险金（A）","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4028895","rdrName":"附加救护车费用保险","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4028720","rdrName":"附加猝死保险","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4001029","rdrName":"火车轮船轨道交通意外身故伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000016","rdrName":"民航班机意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000019","rdrName":"营运汽车意外身故/伤残","rdrRemark":"","sort":0},{"itemNo":1,"plan":"09H00001","rdrAmount":"0","rdrCode":"4000022","rdrName":"非营运汽车意外身故/伤残","rdrRemark":"","sort":0}]}]},"requestHeadVo":{"caller":"M","channelCode":"HT1604763","requestType":"HTIC001"}}`

func main() {
	// 模拟 Java 的 JSONObject.parseObject(message).toJSONString()
	// 这一步主要是为了格式化/压缩 JSON，去除多余空白，确保加密内容一致性
	var jsonMap interface{}
	if err := json.Unmarshal([]byte(OriginalMessage), &jsonMap); err != nil {
		log.Fatalf("JSON 解析失败: %v", err)
	}
	// 重新序列化，Go 的 json.Marshal 默认紧凑格式，类似 FastJSON 的 toJSONString
	messageBytes, err := json.Marshal(jsonMap)
	if err != nil {
		log.Fatalf("JSON 序列化失败: %v", err)
	}
	message := string(messageBytes)

	fmt.Println("原始消息长度:", len(message))

	// 公钥加密
	encryptedStr, err := rsaEncrypt(message, RSAPublicKey)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Println("加密结果 (Base64):")
	fmt.Println(encryptedStr)

	encryptedStr = "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"
	// 私钥解密
	decryptedStr, err := rsaDecrypt(encryptedStr, RSAPrivateKey)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}
	fmt.Println("\n解密结果:")
	fmt.Println(decryptedStr)

	// 验证一致性
	// if decryptedStr == message {
	// 	fmt.Println("\n✅ 加解密成功且内容一致！")
	// } else {
	// 	fmt.Println("\n❌ 加解密后内容不一致！")
	// }
}

// rsaEncrypt 公钥加密 (分段加密)
func rsaEncrypt(content string, publicKeyStr string) (string, error) {
	// 解析公钥
	pubKey, err := parsePublicKey(publicKeyStr)
	if err != nil {
		return "", err
	}

	data := []byte(content)
	inputLen := len(data)
	out := make([]byte, 0)

	// 分段加密
	offSet := 0
	for inputLen-offSet > 0 {
		var block []byte
		var err error

		if inputLen-offSet > MaxEncryptBlock {
			block, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, data[offSet:offSet+MaxEncryptBlock])
			offSet += MaxEncryptBlock
		} else {
			block, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, data[offSet:])
			offSet = inputLen
		}

		if err != nil {
			return "", fmt.Errorf("加密分段失败: %w", err)
		}
		out = append(out, block...)
	}

	// Base64 编码
	encoded := base64.StdEncoding.EncodeToString(out)
	return encoded, nil
}

// rsaDecrypt 私钥解密 (分段解密)
func rsaDecrypt(content string, privateKeyStr string) (string, error) {
	// 解析私钥
	priKey, err := parsePrivateKey(privateKeyStr)
	if err != nil {
		return "", err
	}

	// Base64 解码
	encryptedData, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}

	inputLen := len(encryptedData)
	out := make([]byte, 0)

	// 分段解密
	offSet := 0
	for inputLen-offSet > 0 {
		var block []byte
		var err error

		if inputLen-offSet > MaxDecryptBlock {
			block, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, encryptedData[offSet:offSet+MaxDecryptBlock])
			offSet += MaxDecryptBlock
		} else {
			block, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, encryptedData[offSet:])
			offSet = inputLen
		}

		if err != nil {
			return "", fmt.Errorf("解密分段失败: %w", err)
		}
		out = append(out, block...)
	}

	return string(out), nil
}

// parsePublicKey 解析 X.509/DER 格式的公钥 (Java 中 X509EncodedKeySpec)
func parsePublicKey(keyStr string) (*rsa.PublicKey, error) {
	// 去除可能的头部尾部标记和空白，Java 代码中是直接 Base64 字符串
	keyStr = strings.TrimSpace(keyStr)
	
	// 尝试直接解码 Base64 (Java 代码逻辑)
	byteKey, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("公钥 Base64 解码失败: %w", err)
	}

	// 解析 DER 格式公钥
	pubInterface, err := x509.ParsePKIXPublicKey(byteKey)
	if err != nil {
		return nil, fmt.Errorf("解析公钥 DER 失败: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("不是 RSA 公钥")
	}

	return pubKey, nil
}

// parsePrivateKey 解析 PKCS#8 格式的私钥 (Java 中 PKCS8EncodedKeySpec)
func parsePrivateKey(keyStr string) (*rsa.PrivateKey, error) {
	keyStr = strings.TrimSpace(keyStr)

	// 直接解码 Base64
	byteKey, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("私钥 Base64 解码失败: %w", err)
	}

	// 解析 PKCS#8 格式私钥
	keyInterface, err := x509.ParsePKCS8PrivateKey(byteKey)
	if err != nil {
		return nil, fmt.Errorf("解析私钥 PKCS#8 失败: %w", err)
	}

	priKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("不是 RSA 私钥")
	}

	return priKey, nil
}