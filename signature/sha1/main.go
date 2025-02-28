package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func main() {
	policyNo := "10203113900181656063"
	host := "https://dev1.saas.pengpaibao.com/baoying-product-center/api/policy/correct_url"
	secret := "fd585c3f782a474196748b402e3d1e1f"

	// 构建参数 map
	params := map[string]string{
		"app_id":          "265100_tpGroup1",
		"signature_method": "HMAC-SHA1",
		"version":         "2.0",
		"policyNo":        policyNo,
	}

	// 对参数按 key 排序
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建参数字符串
	var paramString strings.Builder
	for _, k := range keys {
		paramString.WriteString(k)
		paramString.WriteString("=")
		paramString.WriteString(params[k])
		paramString.WriteString("&")
	}
	paramStr := paramString.String()
	paramStr = paramStr[:len(paramStr)-1] // 去掉最后一个 "&"

	// 打印参数字符串
	fmt.Println("Param String:", paramStr)

	// URL 编码
	encodedParamStr := url.QueryEscape(paramStr)
	fmt.Println("Encoded Param String:", encodedParamStr)

	// 构建待签名的字符串
	totalString := fmt.Sprintf("GET&%s&%s&", strings.ToLower(host), encodedParamStr)
	fmt.Println("Total String:", totalString)

	// HMAC-SHA1 签名
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(totalString))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	fmt.Println("Signature:", signature)

	// 构建 Authorization 头
	auth := fmt.Sprintf("OAuth app_id=%s,signature_method=%s,version=%s,signature=%s",
		params["app_id"], params["signature_method"], params["version"], signature)

	fmt.Println("Authorization:", auth)
}