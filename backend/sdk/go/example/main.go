// AuthPro License 文件授权 Go SDK 使用示例
//
// 运行前准备：
//   - 在授权后台「应用管理」查看并复制应用公钥（PEM），保存到 public_key.pem
//   - 在「授权文件」页面签发授权文件，下载后保存为 license.lic
package main

import (
	"log"
	"os"

	"github.com/auth-pro/sdk-go/licensefile"
)

const (
	baseURL   = "https://license.example.com"
	appKey    = "app_xxx"
	appSecret = "sk_live_xxx"
)

func main() {
	// 1. 读取应用公钥（仅服务端私钥签发，客户端只保管公钥）
	publicKey, err := os.ReadFile("public_key.pem")
	if err != nil {
		log.Fatalf("读取公钥失败: %v", err)
	}

	client, err := licensefile.New(baseURL, appKey, appSecret, string(publicKey))
	if err != nil {
		log.Fatalf("初始化 SDK 失败: %v", err)
	}

	// 2. 可选：自定义心跳缓存文件（默认在系统临时目录）
	client.CacheFile = ".runtime/license-heartbeat.json"

	// 3. 完整校验：离线验签 + 心跳回源（回源失败进入宽限期）
	ctx := licensefile.Context{
		Domain:    "example.com",           // 留空自动采集
		MachineID: licensefile.MachineID(), // 留空自动采集
	}
	if err := client.CheckFile("license.lic", ctx); err != nil {
		log.Fatalf("授权无效: %v", err)
	}
	log.Println("授权有效")

	// 4. 纯离线校验示例（不发起任何网络请求）
	fileContent, err := os.ReadFile("license.lic")
	if err != nil {
		log.Fatalf("读取授权文件失败: %v", err)
	}
	payload, err := licensefile.Parse(fileContent)
	if err != nil {
		log.Fatalf("解析授权文件失败: %v", err)
	}
	if err := client.VerifyOffline(payload, ctx); err != nil {
		log.Fatalf("离线校验失败: %v", err)
	}
	log.Printf("离线校验通过：文件编号 %s，到期时间 %s", payload.FileNo, payload.ExpireAt)
}
