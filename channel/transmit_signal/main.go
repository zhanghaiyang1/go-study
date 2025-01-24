package main

import (
	"fmt"
	// "time"
)

/*
无缓冲 channel 可用于两个 goroutine 之间传递信号
*/
func main(){
	block := make(chan struct{})

	go odd(block)
	go even(block)
	// time.Sleep(time.Second)
	fmt.Println("Done")
}
func odd(block chan struct{}){
	for i := 1; i <= 100; i++ {
		<- block
		if i & 1 == 1 {
			fmt.Println(i)
		}
	}
}
func even(block chan struct{}){
	for i := 1; i <= 100; i++ {
		block <- struct{}{}
		if i & 1 == 0 {
			fmt.Println(i)
		}
	}	
}