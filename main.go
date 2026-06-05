package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/jordan-wright/email"
)

func main() {
	// 配置信息
	username := "ocean@bbyfu.cn"
	password := "haiyang@1017"
	replyto := username
	// 显示的To收信地址
	rcptto := []string{"z_haiyang@163.com"}
	//# 显示的Cc收信地址
	rcptcc := []string{"zhangna@bbyfu.cn", "kuangwenjing@bbyfu.cn"}
	//# Bcc收信地址，密送人不会显示在邮件上，但可以收到邮件
	rcptbcc := []string{"z_jiale2022@163.com"}
	receivers := append(rcptto, rcptcc...)
	receivers = append(receivers, rcptbcc...)

	// 创建邮件
	e := email.NewEmail()
	e.From = "\"自定义发信昵称\" <" + username + ">"
	e.To = rcptto
	e.Cc = rcptcc
	e.Bcc = rcptbcc
	e.ReplyTo = []string{replyto}
	e.Subject = "自定义信件主题"

	// 设置Message-ID
	e.Headers = make(textproto.MIMEHeader)
	e.Headers.Set("Message-ID", generateMessageID())
	e.Headers.Set("Return-Path", "test@example.net")

	// 设置HTML内容
	e.HTML = []byte("自定义HTML超文本部分")

	// 可选：设置纯文本内容
	// e.Text = []byte("自定义TEXT纯文本部分")

	// 可选：添加本地附件
	// file, err := os.Open("test.jpg")
	// if err != nil {
	// 	fmt.Println("打开附件失败:", err)
	// 	return
	// }
	// defer file.Close()
	// e.Attach(file, "test.jpg", "image/jpeg")

	// 可选：添加URL附件
	// e.AttachFile("https://example.oss-cn-shanghai.aliyuncs.com/xxxxxxxxxxx.png")

	// 发送邮件
	err := sendEmail(e, username, password, "smtp.qiye.aliyun.com", 25)
	if err != nil {
		fmt.Println("邮件发送失败:", err)
		return
	}
	fmt.Println("邮件发送成功！")
}

// sendEmail 发送邮件
func sendEmail(e *email.Email, username, password, host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)

	// 普通SMTP连接
	if port == 25 {
		return e.Send(addr, smtp.PlainAuth("", username, password, host))
	}

	// SSL连接 (端口465)
	if port == 465 {
		return e.SendWithTLS(addr, smtp.PlainAuth("", username, password, host), &tls.Config{
			ServerName: host,
		})
	}

	return fmt.Errorf("不支持的端口: %d", port)
}

// generateMessageID 生成Message-ID
func generateMessageID() string {
	return fmt.Sprintf("<%d.%d@example.com>", time.Now().UnixNano(), os.Getpid())
}

// 以下为不使用第三方库的原生实现示例（可选）
func sendEmailNative() error {
	from := mail.Address{Name: "自定义发信昵称", Address: "sender@example.com"}
	to := []mail.Address{
		{Name: "", Address: "address1@example.net"},
		{Name: "", Address: "address2@example.net"},
	}

	// 设置邮件头
	headers := make(textproto.MIMEHeader)
	headers.Set("From", from.String())
	headers.Set("To", formatAddresses(to))
	headers.Set("Subject", "自定义信件主题")
	headers.Set("Message-ID", generateMessageID())
	headers.Set("Date", time.Now().Format(time.RFC1123Z))

	// 创建邮件内容
	body := "自定义HTML超文本部分"

	// 连接到SMTP服务器
	client, err := smtp.Dial("smtp.qiye.aliyun.com:25")
	if err != nil {
		return err
	}
	defer client.Close()

	// 认证
	if err := client.Auth(smtp.PlainAuth("", "username", "password", "smtp.qiye.aliyun.com")); err != nil {
		return err
	}

	// 设置发件人
	if err := client.Mail(from.Address); err != nil {
		return err
	}

	// 设置收件人
	toAddresses := make([]string, len(to))
	for i, addr := range to {
		toAddresses[i] = addr.Address
	}
	for _, addr := range toAddresses {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}

	// 发送数据
	w, err := client.Data()
	if err != nil {
		return err
	}

	// 写入邮件头
	for k, v := range headers {
		fmt.Fprintf(w, "%s: %s\r\n", k, strings.Join(v, ", "))
	}
	fmt.Fprintf(w, "\r\n")
	// 写入邮件体
	io.WriteString(w, body)

	w.Close()
	return nil
}

// formatAddresses 格式化地址列表
func formatAddresses(addrs []mail.Address) string {
	var formatted []string
	for _, addr := range addrs {
		formatted = append(formatted, addr.String())
	}
	return strings.Join(formatted, ", ")
}
