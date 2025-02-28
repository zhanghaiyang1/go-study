package main

import (
    "fmt"
    // "time"
)

func main() {
    ch := make(chan int, 5) // 创建一个容量为5的带缓冲通道

    // 向通道写入5个值
    for i := 1; i <= 5; i++ {
        ch <- i
        fmt.Printf("Wrote %d to channel\n", i)
    }

    // 尝试写入第6个值，这将导致阻塞
    go func() {
        ch <- 6
        fmt.Println("Wrote 6 to channel")
    }()

    // 读取通道中的值以释放空间
    // time.Sleep(1 * time.Second) // 给goroutine一些时间启动
    for i := 1; i <= 6; i++ {
        value := <-ch
        fmt.Printf("Read %d from channel\n", value)
    }
}