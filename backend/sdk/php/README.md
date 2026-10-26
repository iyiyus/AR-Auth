# AuthPro PHP SDK

AuthPro 授权站 PHP 接入 SDK，封装 `/api/license/verify` 授权校验的签名、请求与结果判定。

## 环境要求

- PHP 7.0+
- cURL 扩展

## 包内容

| 文件 | 说明 |
| --- | --- |
| `AuthProLicense.php` | 在线授权校验 SDK 主类（`/api/license/verify`） |
| `AuthProLicenseFile.php` | License 文件授权 SDK（离线验签 + 心跳回源） |
| `example.php` | 在线校验入口接入示例 |
| `example_license_file.php` | License 文件授权接入示例 |
| `README.md` | 本文档 |

## 快速接入

1. 把 `AuthProLicense.php` 复制到你的项目中。
2. 在站点入口文件顶部加入：

```php
<?php
require_once __DIR__ . '/AuthProLicense.php';

$sdk = new AuthProLicense(
    'https://license.example.com', // 授权站地址
    'your_app_key',                // 应用的 appKey
    'your_app_secret'              // 应用的 appSecret
);

if (!$sdk->verify()) {
    http_response_code(403);
    exit('License invalid: ' . $sdk->getLastError());
}

// 授权通过，继续业务代码
```

也可以使用 `verifyOrExit()` 一行完成守卫：

```php
$sdk->verifyOrExit(); // 失败时自动 403 并输出原因
```

## API

### `__construct($baseUrl, $appKey, $appSecret, $timeout = 8)`

- `$baseUrl`：授权站地址，不带尾随斜杠。
- `$appKey` / `$appSecret`：AuthPro 后台「应用管理」中对应应用的密钥对。
- `$timeout`：请求超时时间（秒），默认 8。

### `verify($domain = '', $serverIp = '', $licenseKey = '')`

校验授权，返回 `true` / `false`。

- `$domain` 留空时自动取 `$_SERVER['HTTP_HOST']`（去掉端口）。
- `$serverIp` 留空时自动取 `$_SERVER['SERVER_ADDR']`。
- 应用使用授权码（卡密）时，把用户填写的授权码作为 `$licenseKey` 传入；否则留空。

### `getLastError()`

返回最近一次失败原因（网络错误、授权无效等），便于排查。

### `getLastResponse()`

返回最近一次接口返回的完整数组，调试时可用。

## 校验规则（与后台「SDK 示例」页面一致）

- 接口：`POST /api/license/verify`，`Content-Type: application/json`
- v2 签名：`HMAC-SHA256(appSecret, "v2\nappKey\nlicenseKey\ndomain\nserverIp\ntimestamp")`，空字段保留空行
- 域名 / IP 规范化：SDK 在签名前会对 domain、serverIp 做与服务端一致的规范化（小写、去协议头与端口、去结尾点号、IPv6 转压缩标准形），保证双方签名串一致
- 时间窗口：`timestamp` 与服务器时间误差需在 10 分钟内，请保证业务服务器时间准确（建议配置 NTP）
- 通过条件：返回 JSON 中 `code = 200` 且 `data.result = pass`

## License 文件授权（离线）

文件授权适用于**离线部署 / 内网部署**场景：授权服务端用应用 RSA-2048 私钥签发授权文件，
客户只需部署授权文件和公钥即可本地验签，仅在心跳周期到达时联网回源一次。

### 快速接入

```php
<?php
require_once __DIR__ . '/AuthProLicenseFile.php';

$sdk = new AuthProLicenseFile(
    'https://license.example.com', // 授权站地址
    'your_app_key',                // appKey
    'your_app_secret',             // appSecret（心跳回源签名用）
    $publicKeyPem                  // 应用 License 文件公钥 PEM
);

// check() 内部：离线验签 → 到心跳窗口则回源 → 回源失败进入宽限期
if (!$sdk->check(__DIR__ . '/license-APPKEY-LF20260101ABCDEFGH.lic')) {
    http_response_code(403);
    exit('License invalid: ' . $sdk->getLastError());
}
```

也可以一行守卫：`$sdk->guard($licenseFile);`

### 主要 API

| 方法 | 说明 |
| --- | --- |
| `__construct($baseUrl, $appKey, $appSecret, $publicKey, $timeout = 8, $cacheFile = null)` | 创建 SDK，可指定心跳缓存文件 |
| `parse($content)` | 静态解析授权文件（装甲格式或裸 JSON） |
| `verifyOffline($payload, $domain = '', $serverIp = '', $machineId = '')` | 纯离线校验，不联网 |
| `check($licenseFile, $options = [])` | 离线 + 心跳 + 宽限期的完整校验 |
| `guard($licenseFile, $options = [], $message = 'License invalid')` | 失败直接 403 退出 |
| `machineId($salt = null)` | 采集稳定的机器码指纹 |

### 校验规则

- 验签算法：RSA-SHA256（PKCS#1 v1.5），公钥随文件下发，私钥不出服务端
- 环境绑定：域名（支持 `*.example.com` 泛域名）、服务器 IP、机器码，三类任选，**每个非空维度都必须命中**
- 心跳回源：`POST /api/license/file/verify`，请求签名 `HMAC-SHA256(appSecret, "v3\nappKey\ndomain\nserverIp\nmachineId\ntimestamp")`
- 离线宽限：回源失败时在 `graceDays` 天内仍放行，超出才失效；`heartbeatDays = 0` 表示纯离线不回源

## 常见问题

- **提示「网络请求失败」**：检查业务服务器能否访问授权站地址、防火墙与 DNS。
- **提示「授权文件未绑定当前域名 / 机器码」**：授权文件签发时绑定了运行环境，需在后台重新签发并填写正确的域名、IP 或机器码。
- **提示「心跳回源失败且已超出离线宽限期」**：服务器长时间无法访问授权站，请检查出网或被墙情况。
- **提示签名相关错误**：确认 appKey / appSecret 与应用匹配，且服务器时间误差在 10 分钟内。
- **Apache / Nginx 下获取不到域名**：SDK 默认取 `HTTP_HOST`，反向代理场景请显式传 `$domain`。
- **生产环境建议缓存校验结果**（如 10~30 分钟），避免每个请求都调用授权接口影响性能。
