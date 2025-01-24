package main

import (
	"fmt"
)

func quickSort(arr []int, low, high int) {
	if low < high {
		// pi 是分区操作后的基准元素的索引
		pi := partition(arr, low, high)

		// 递归地排序基准元素左边和右边的元素
		quickSort(arr, low, pi-1)
		quickSort(arr, pi+1, high)
	}
}
//Ocean@0712
func partition(arr []int, low, high int) int {
	// 选择最右边的元素作为基准
	pivot := arr[high]
	i := low - 1 // i 是小于基准的元素的索引

	for j := low; j < high; j++ {
		// 如果当前元素小于或等于基准
		if arr[j] <= pivot {
			i++
			arr[i], arr[j] = arr[j], arr[i]
		}
	}
	arr[i+1], arr[high] = arr[high], arr[i+1]
	return i + 1
}

func main() {
	arr := []int{10, 7, 4, 9, 1, 5}
	n := len(arr)
	quickSort(arr, 0, n-1)
	fmt.Println("Sorted array is:", arr)
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