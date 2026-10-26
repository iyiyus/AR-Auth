# AuthPro License 文件授权 SDK（Go）

Go 侧 License 文件授权校验 SDK，用于服务端签发、客户端离线验证的商业软件授权场景。

## 能力

| 能力 | 说明 |
|------|------|
| 离线验签 | RSA-2048 + SHA-256（PKCS#1 v1.5），仅持有公钥即可完成本地校验 |
| 运行环境绑定 | 域名（支持 `*.example.com` 泛域名）、服务器 IP、机器码三类可选绑定 |
| 心跳回源 | 默认按 `heartbeatDays` 周期校验一次，同步吊销与黑名单状态 |
| 离线宽限 | 回源失败时按 `graceDays` 容忍离线，超出才判定失效 |
| 机器指纹 | `MachineID()` 采集主机名 + MAC 地址做 SHA-256 |

## 安装

```bash
go get github.com/auth-pro/sdk-go/licensefile
```

直接 vendored 使用：把 `licensefile.go` 拷入项目即可（仅依赖标准库）。

## 快速开始

```go
client, err := licensefile.New("https://license.example.com", appKey, appSecret, publicKeyPEM)
if err != nil {
    log.Fatal(err)
}
client.CacheFile = ".runtime/license-heartbeat.json"

ctx := licensefile.Context{Domain: "example.com", MachineID: licensefile.MachineID()}
if err := client.CheckFile("license.lic", ctx); err != nil {
    log.Fatalf("授权无效: %v", err)
}
```

## API

| 函数/方法 | 说明 |
|-----------|------|
| `New(baseURL, appKey, appSecret, publicKeyPEM)` | 创建客户端并解析公钥 |
| `Parse(content)` | 解析授权文件（装甲格式或裸 JSON） |
| `VerifyOffline(payload, ctx)` | 纯离线校验：验签 + 有效期 + 绑定 |
| `CheckFile(path, ctx)` | 读取文件后执行完整校验（含心跳） |
| `Check(content, ctx)` | 完整校验，支持自定义宽限/缓存策略 |
| `MachineID()` | 采集稳定的机器指纹 |

## 失败原因（常见）

| 错误信息 | 处理建议 |
|----------|----------|
| 授权文件签名校验失败 | 文件被篡改或应用密钥对已轮换，请重新签发 |
| 授权文件未绑定当前域名/IP/机器码 | 在后台重新签发授权文件并补充运行环境信息 |
| 授权已过期 | 续费或延长到期时间 |
| 授权文件已吊销 | 文件被后台吊销，联系服务商处理 |
| 心跳回源失败 | 网络不可达，宽限期内仍可运行；持续失败请检查白名单与出站网络 |

## 注意事项

- 公钥可与业务代码一起分发，**私钥始终保存在授权服务端**，切勿下发。
- 心跳缓存文件所在目录需要写权限；容器场景建议挂载可写卷。
- `heartbeatDays = 0` 表示纯离线授权，SDK 不会发起任何回源请求（吊销状态无法同步）。
