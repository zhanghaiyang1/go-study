package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
)

// Prize 定义奖品结构
type Prize struct {
	Name     string  // 奖品名称
	Chance   float64 // 中奖概率（百分比）
	Quantity int     // 奖品剩余数量
}

// Draw 抽奖函数
func Draw(prizes []Prize) string {
	rand.Seed(time.Now().UnixNano()) // 初始化随机数种子
	r := rand.Float64() * 100        // 生成 0-100 之间的随机数

	ctx := gctx.New()
	g.Log().Infof(ctx, "r:%f", r)
	var cumulativeChance float64
	for i := range prizes {
		cumulativeChance += prizes[i].Chance
		if r <= cumulativeChance {
			if prizes[i].Quantity > 0 {
				prizes[i].Quantity-- // 减少奖品数量
				return prizes[i].Name // 返回中奖奖品名称
			}
			break // 如果奖品数量为 0，跳过该奖品
		}
	}

	return "未中奖" // 如果没有中奖
}

func main() {
	// 初始化奖品池
	prizes := []Prize{
		{Name: "三等奖", Chance: 15, Quantity: 30}, // 15% 中奖概率，30 个奖品
		{Name: "二等奖", Chance: 10, Quantity: 20},  // 10% 中奖概率，20 个奖品
		{Name: "一等奖", Chance: 5, Quantity: 10},   // 5% 中奖概率，10 个奖品
	}

	// 模拟 100 次抽奖
	for i := 0; i < 100; i++ {
		result := Draw(prizes)
		fmt.Printf("第 %d 次抽奖结果: %s\n", i+1, result)
	}

	// 打印剩余奖品数量
	fmt.Println("\n剩余奖品数量:")
	for _, prize := range prizes {
		fmt.Printf("%s: %d\n", prize.Name, prize.Quantity)
	}
}