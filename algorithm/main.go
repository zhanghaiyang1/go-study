package main

import "fmt"


func main(){
	longestNonRepeatStr()
}
//最长无重复字符子字符串
func longestNonRepeatStr(){
	originStr := "lskadjflaksjdfoqweqwfasdf"
	fmt.Println(originStr)
    
}


/*
func longestNonRepeatingSubStr(s string) string {
    lastOccurred := make(map[rune]int)
    start := 0
    maxLength := 0
    maxStart := 0

    for i, ch := range []rune(s) {
        if lastI, ok := lastOccurred[ch]; ok && lastI >= start {
            start = lastI + 1
        }
        if i-start+1 > maxLength {
            maxLength = i - start + 1
            maxStart = start
        }
        lastOccurred[ch] = i
    }

    return string([]rune(s)[maxStart : maxStart+maxLength])
}
*/