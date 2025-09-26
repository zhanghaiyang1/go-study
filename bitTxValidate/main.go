package main

import (
	"fmt"
	"regexp"
)

// isBitcoinTXID 检查字符串是否符合 Bitcoin TXID 的格式
func isBitcoinTXID(s string) bool {
	// 步骤 1：检查长度是否为 64
	if len(s) != 64 {
		return false
	}
	// 步骤 2：检查是否只包含小写十六进制字符 (0-9, a-f)
	match, _ := regexp.MatchString("^[0-9a-f]{64}$", s)
	return match
}

func main() {
	// 测试用例
	testCases := []string{
		"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", // 有效
		"0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", // 无效（有前缀）
		"123",                                   // 无效（太短）
		"Invalid!",                              // 无效（非法字符）
		"1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B", // 无效（大写）
	}

	for _, tc := range testCases {
		fmt.Printf("字符串: %s, 是否有效: %v\n", tc, isBitcoinTXID(tc))
	}
}