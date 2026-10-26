<?php
/**
 * AuthPro License 文件授权 PHP SDK 接入示例
 *
 * 用法：
 *   1. 在授权后台「系统管理 → 应用管理」查看应用的 License 文件公钥，保存到 public_key.pem
 *   2. 在「授权管理 → 授权文件」为类型为「文件授权」的授权签发文件，下载 license-xxx.lic
 *   3. 把 AuthProLicenseFile.php、public_key.pem、license-xxx.lic 放在同一目录后运行本示例
 */
require_once __DIR__ . '/AuthProLicenseFile.php';

$publicKeyFile = __DIR__ . '/public_key.pem';
$licenseFile = __DIR__ . '/license-APPKEY-LF20260101ABCDEFGH.lic';

if (!is_file($publicKeyFile) || !is_file($licenseFile)) {
    exit("请先把 public_key.pem 与 license-xxx.lic 放到本目录\n");
}

$sdk = new AuthProLicenseFile(
    'https://license.example.com', // 授权站地址（你的 AuthPro 站点）
    'your_app_key',                // 后台应用管理里的 appKey
    'your_app_secret',             // 后台应用管理里的 appSecret（心跳回源签名用）
    file_get_contents($publicKeyFile) // 应用 License 文件公钥
);

// 可选：指定心跳缓存文件（默认在系统临时目录），目录需有写权限
// $sdk = new AuthProLicenseFile($baseUrl, $appKey, $appSecret, $publicKey, 8, __DIR__ . '/.runtime/heartbeat.json');

// check() 流程：离线验签 → 到心跳周期则回源 → 回源失败时在宽限期内仍放行
if (!$sdk->check($licenseFile, array('domain' => 'example.com'))) {
    http_response_code(403);
    exit('License invalid: ' . $sdk->getLastError() . "\n");
}

// ===== 授权通过，下面是你的业务代码 =====
echo "授权有效，业务正常运行\n";
echo '本机机器码：' . AuthProLicenseFile::machineId() . "\n";
