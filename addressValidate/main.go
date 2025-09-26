package main

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

// isBitcoinAddress 检查是否为 Bitcoin 地址（P2PKH, P2SH, Bech32）
func isBitcoinAddress(s string) bool {
	// P2PKH: 25-34 字符，以 1 开头
	p2pkhPattern := `^[1][a-km-zA-HJ-NP-Z1-9]{25,34}$`
	// P2SH: 34 字符，以 3 开头
	p2shPattern := `^[3][a-km-zA-HJ-NP-Z1-9]{33}$`
	// Bech32: 42 或 62 字符，以 bc1 开头
	bech32Pattern := `^bc1[a-z0-9]{39,59}$`

	p2pkh, err1 := regexp.MatchString(p2pkhPattern, s)
	if err1 == nil && p2pkh {
		return true
	}
	p2sh, err2 := regexp.MatchString(p2shPattern, s)
	if err2 == nil && p2sh {
		return true
	}
	bech32, err3 := regexp.MatchString(bech32Pattern, s)
	return err3 == nil && bech32
}

// isSolanaAddress 检查是否为 Solana 地址
func isSolanaAddress(s string) bool {
	// Solana 地址通常是 32-44 字符的 Base58 编码
	// 不以 1, 3 或 bc1 开头（避免与 Bitcoin 地址冲突）
	if len(s) < 32 || len(s) > 44 {
		return false
	}
	// 排除以 1, 3 或 bc1 开头的地址（避免与 Bitcoin 地址冲突）
	if s[0] == '1' || s[0] == '3' || (len(s) > 3 && s[:3] == "bc1") {
		return false
	}
	pattern := `^[1-9A-HJ-NP-Za-km-z]{32,44}$`
	match, err := regexp.MatchString(pattern, s)
	return err == nil && match
}

// isEVMAddress 检查是否为 EVM 地址
func isEVMAddress(s string) bool {
	// 长度：42 字符（0x + 40 十六进制）
	if len(s) != 42 || s[:2] != "0x" {
		return false
	}
	// 检查是否为十六进制
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// base58Decode 模拟 Base58 解码（简单实现）
func base58Decode(s string) ([]byte, error) {
	// 这里需要完整的 Base58 解码实现，省略具体逻辑
	// 可使用 github.com/btcsuite/btcutil/base58 库
	return nil, nil
}

func main() {
	testCases := []string{
		"1PMycacnJaSqwwJqjawXBErnLsZ7Z5rM",             // Bitcoin P2PKH
		"3E5fR6mxc4jAc1e1a9A2b3c4d5e6f7g8h9",           // Bitcoin P2SH
		"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",   // Bitcoin Bech32
		"6bpqEtc4o8MQeqErp6NtGJ49j8sgs3e29cD9LBZgoukA", // Solana
		"0x8f5419c8797cbdecaf3f2f1910d192f4306d527d",   // EVM
		"invalid", // 无效
	}

	for _, addr := range testCases {
		fmt.Printf("地址: %s\n", addr)
		if isBitcoinAddress(addr) {
			fmt.Println("  可能是 Bitcoin 地址")
		}
		if isSolanaAddress(addr) {
			fmt.Println("  可能是 Solana 地址")
		}
		if isEVMAddress(addr) {
			fmt.Println("  可能是 EVM 链地址")
		}
		if !isBitcoinAddress(addr) && !isSolanaAddress(addr) && !isEVMAddress(addr) {
			fmt.Println("  无效地址")
		}
		fmt.Println()
	}
}
