package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	apiKey  = "a6122220-ca73-49c5-8b05-95e86d224d68"
	address = "6bpqEtc4o8MQeqErp6NtGJ49j8sgs3e29cD9LBZgoukA"
	limit   = 100
)

type Transaction struct {
	Signature string `json:"signature"`
	// 可以根据需要添加更多字段
}

func fetchTransactions(before string) ([]Transaction, error) {
	url := fmt.Sprintf("https://api.helius.xyz/v0/addresses/%s/transactions?api-key=%s&limit=%d", address, apiKey, limit)
	if before != "" {
		url += "&before=" + before
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP 响应状态错误: %s", resp.Status)
	}

	body, _ := ioutil.ReadAll(resp.Body)

	var transactions []Transaction
	err = json.Unmarshal(body, &transactions)
	if err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}

	return transactions, nil
}

func main() {
	start := time.Now() // 开始计时

	total := 0
	before := ""
	page := 1

	for {
		fmt.Printf("获取第 %d 页交易...\n", page)
		transactions, err := fetchTransactions(before)
		if err != nil {
			fmt.Println("获取交易失败：", err)
			break
		}

		count := len(transactions)
		total += count

		if count < limit {
			break
		}

		before = transactions[count-1].Signature
		page++
	}

	elapsed := time.Since(start) // 结束计时
	fmt.Printf("地址 %s 的交易总数为：%d\n", address, total)
	fmt.Printf("执行耗时：%s\n", elapsed)
}
