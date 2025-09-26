package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type botAi struct {
	urlStr   string
	sk       string
	Model    string                   `json:"model"`
	Messages []map[string]interface{} `json:"messages"`
	chat     string
}

func NewBotAi(sk string) *botAi {
	return &botAi{
		urlStr:   "https://api.suanli.cn/v1/chat/completions",
		sk:       fmt.Sprintf("Bearer %s", sk),
		Model:    "deepseek-r1:7b",
		Messages: make([]map[string]interface{}, 0),
	}
}
func (b *botAi) Chat(msg string) {
	b.Messages = append(b.Messages, map[string]interface{}{
		"role":    "user",
		"content": msg,
	})
	jsonData, err := json.Marshal(b)
	if err != nil {
		log.Println(err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, b.urlStr, bytes.NewReader(jsonData))
	if err != nil {
		log.Println(err)
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", b.sk)
	var client = http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}
	respData := map[string]interface{}{}
	if err := json.Unmarshal(result, &respData); err != nil {
		log.Println(err)
		return
	}
	var str = respData["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"]
	newStr := strings.Trim(str.(string), "<think>")
	newStr = strings.Trim(newStr, "</think>")
	newStr = strings.Trim(newStr, "\n")
	b.chat = newStr
}
func (b *botAi) Process() {
	emptyLines := []string{}
	sliceStr := strings.Split(b.chat, "</think>")
	newStr := strings.TrimSpace(sliceStr[0])
	newSliceStr := strings.Split(newStr, "\n")
	for _, v := range newSliceStr {
		if v != "" {
			emptyLines = append(emptyLines, v)
		}
	}
	s := strings.Join(emptyLines, "\n")
	b.chat = s + sliceStr[1]
}
func menu() {
	fmt.Println("\t\t\t\t*************************************************")
	fmt.Println("\t\t\t\t*\t\t欢迎使用AI智能助手\t\t*")
	fmt.Println("\t\t\t\t*\t\t\t\t\t\t*")
	fmt.Println("\t\t\t\t*\t\t输入:退出 退出程序\t\t*")
	fmt.Println("\t\t\t\t*************************************************")
}
func main() {
	menu()
	bot := NewBotAi("sk-W0rpStc95T7JVYVwDYc29IyirjtpPPby6SozFMQr17m8KWeo")
	flagState := true
	for flagState {
		read := bufio.NewReader(os.Stdin)
		fmt.Print("输入会话:")
		inputStr, err := read.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		if strings.Contains(inputStr, "退出") {
			flagState = false
			return
		}
		bot.Chat(inputStr)
		bot.Process()
		fmt.Println(bot.chat)
	}
}
