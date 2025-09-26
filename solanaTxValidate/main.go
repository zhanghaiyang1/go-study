package main

import (
	"fmt"
	"github.com/mr-tron/base58"
	"strings"
)

// Base58 character set
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Method 1: Check string length and character set
func checkLengthAndCharset(s string) bool {
	if len(s) != 88 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(base58Alphabet, c) {
			return false
		}
	}
	return true
}

// Method 2: Check Base58-decoded byte length
func checkDecodedLength(s string) bool {
	decoded, err := base58.Decode(s)
	if err != nil {
		return false
	}
	return len(decoded) == 64
}

// Combine both methods to validate Solana transaction hash
func isSolanaTransactionHash(s string) bool {
	if !checkLengthAndCharset(s) {
		return false
	}
	return checkDecodedLength(s)
}

func main() {
	// Test cases
	testStrings := []string{
		"4SNQ4h1vL9GkmSnojQsf8SZyFvQsaq62RCgops2UXFYag1Jc4MoWrjTg2ELwMqM1tQbn9qUcNc4tqX19EGHBqC5u", // Valid
		"2MKcR9RD4QnZ3YSKAZqBYyegdgxJJV8dLj5vgT8r7hnYdqAdKTo1riy4NGXCbtZ7UYVCYfUxHgppggunKjgBKSrR",
		"InvalidLengthString", // Wrong length
		"InvalidChar!String",  // Invalid characters
		"ShortBase58String1234567890", // Too short
	}

	for _, s := range testStrings {
		if isSolanaTransactionHash(s) {
			fmt.Printf("%s: 是Solana交易哈希\n", s)
		} else {
			fmt.Printf("%s: 不是Solana交易哈希\n", s)
		}
	}
}