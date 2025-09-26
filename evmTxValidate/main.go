package main

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Method 2: Check hex-decoded byte length
func checkDecodedLength(s string) bool {
    if !checkLengthAndHex(s) {
        return false
    }
    hexPart := s[2:] // Remove "0x"
    decoded, err := hex.DecodeString(hexPart)
    if err != nil {
        return false
    }
    return len(decoded) == 32
}

// Method 1: Check length and hex character set (from previous method)
func checkLengthAndHex(s string) bool {
    if len(s) != 66 {
        return false
    }
    if !strings.HasPrefix(s, "0x") {
        return false
    }
    hexPart := s[2:]
    match, _ := regexp.MatchString("^[0-9a-fA-F]{64}$", hexPart)
    return match
}

func main() {
    testStrings := []string{
        "0x7e4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a", // Valid
        "0x123", // Too short
        "0xInvalidHex!", // Invalid characters
        "7e4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a6f4a0f4a", // Missing 0x
    }

    for _, s := range testStrings {
        if checkDecodedLength(s) {
            fmt.Printf("%s: 可能是 Ethereum 交易哈希\n", s)
        } else {
            fmt.Printf("%s: 不是 Ethereum 交易哈希\n", s)
        }
    }
}