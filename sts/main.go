package main

import (
	"fmt"
	"os"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts20150401 "github.com/alibabacloud-go/sts-20150401/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
)

func main() {
	// 从环境变量读取，绝对安全
	accessKeyId := os.Getenv("ALIBABA_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_ACCESS_KEY_SECRET")
	roleArn := os.Getenv("ALIBABA_ROLE_ARN")

	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
	}
	config.Endpoint = tea.String("sts.cn-shanghai.aliyuncs.com")
	client, err := sts20150401.NewClient(config)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	request := &sts20150401.AssumeRoleRequest{
		DurationSeconds: tea.Int64(3600),
		RoleArn:         tea.String(roleArn),
		RoleSessionName: tea.String("examplename"),
	}
	response, err := client.AssumeRoleWithOptions(request, &util.RuntimeOptions{})
	if err != nil {
		fmt.Printf("Failed to assume role: %v\n", err)
		return
	}

	credentials := response.Body.Credentials
	fmt.Println("AccessKeyId:", tea.StringValue(credentials.AccessKeyId))
	fmt.Println("AccessKeySecret:", tea.StringValue(credentials.AccessKeySecret))
	fmt.Println("SecurityToken:", tea.StringValue(credentials.SecurityToken))
	fmt.Println("Expiration:", tea.StringValue(credentials.Expiration))
}