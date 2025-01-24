package main

import (
	"fmt"
	// "time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
)

/*
无缓冲 channel 作为主子 goroutine 之间的信号传递的桥梁。通过信号传递，主 goroutine 在子 goroutine 运行结束之后再退出。
*/
func main(){
	block := make(chan struct{})
	ctx := gctx.New()
	go func ()  {
		// time.Sleep(time.Second * 1)
		g.Log().Infof(ctx, "子")
		block <- struct{}{}
		close(block)
	}()
	<- block
	fmt.Println("Done")
}

