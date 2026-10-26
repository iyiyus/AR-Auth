<?php
/**
 * AuthProLicenseFile - AuthPro License 文件授权 PHP SDK
 *
 * 授权文件由授权服务端的应用 RSA-2048 私钥签发，本 SDK 只持有公钥即可本地验签，
 * 无需每次启动都联网；仅在心跳周期到达时回源一次，用于同步吊销与黑名单状态。
 *
 * 依赖：PHP 7.2+，openssl 扩展（离线验签），cURL 扩展（心跳回源）。
 */
class AuthProLicenseFile
{
    /** @var string 授权站地址，例如 https://license.example.com */
    private $baseUrl;

    /** @var string 应用的 appKey */
    private $appKey;

    /** @var string 应用的 appSecret，用于心跳回源的请求签名 */
    private $appSecret;

    /** @var string 应用的 License 文件公钥（PEM），后台「应用管理」可查看 */
    private $publicKey;

    /** @var int 心跳回源超时时间（秒） */
    private $timeout;

    /** @var string 最近一次失败原因 */
    private $lastError = '';

    /** @var string|null 离线心跳缓存文件路径 */
    private $cacheFile;

    /**
     * @param string      $baseUrl    授权站地址，不带尾随斜杠
     * @param string      $appKey     应用 appKey
     * @param string      $appSecret  应用 appSecret
     * @param string      $publicKey  应用 License 文件公钥 PEM
     * @param int         $timeout    回源超时秒数，默认 8
     * @param string|null $cacheFile  心跳缓存文件路径，默认位于系统临时目录
     */
    public function __construct($baseUrl, $appKey, $appSecret, $publicKey, $timeout = 8, $cacheFile = null)
    {
        $this->baseUrl = rtrim(trim($baseUrl), '/');
        $this->appKey = trim($appKey);
        $this->appSecret = $appSecret;
        $this->publicKey = $publicKey;
        $this->timeout = max(1, (int) $timeout);
        $this->cacheFile = $cacheFile !== null && $cacheFile !== ''
            ? $cacheFile
            : sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'authpro_license_' . md5($this->appKey) . '.json';
    }

    /** @return string 最近一次失败原因，成功时为空字符串 */
    public function getLastError()
    {
        return $this->lastError;
    }

    /**
     * 读取授权文件（支持装甲格式原文或裸 JSON）。
     *
     * @param string $content 文件内容（可直接传 file_get_contents($path) 的结果）
     * @return array|null 解析失败返回 null
     */
    public static function parse($content)
    {
        $text = trim($content);
        if ($text === '') {
            return null;
        }
        if (strpos($text, '-----BEGIN AUTH PRO LICENSE FILE-----') !== false) {
            $text = str_replace(
                array('-----BEGIN AUTH PRO LICENSE FILE-----', '-----END AUTH PRO LICENSE FILE-----'),
                '',
                $text
            );
            $decoded = base64_decode(preg_replace('/\s+/', '', $text), true);
            if ($decoded === false) {
                return null;
            }
            $text = trim($decoded);
        }
        $payload = json_decode($text, true);
        return is_array($payload) ? $payload : null;
    }

    /**
     * 离线校验：验签 + 有效期 + 运行环境绑定，完全不联网。
     *
     * @param array  $payload       parse() 得到的授权文件数据
     * @param string $domain        当前访问域名，留空自动取 $_SERVER['HTTP_HOST']
     * @param string $serverIp      当前服务器 IP，留空自动取 $_SERVER['SERVER_ADDR']
     * @param string $machineId     当前机器码，留空自动采集
     * @return bool
     */
    public function verifyOffline($payload, $domain = '', $serverIp = '', $machineId = '')
    {
        $this->lastError = '';

        if (!is_array($payload)) {
            $this->lastError = '授权文件解析失败';
            return false;
        }
        if ($this->publicKey === '') {
            $this->lastError = 'SDK 未配置应用 License 公钥';
            return false;
        }
        if (isset($payload['appKey']) && $payload['appKey'] !== $this->appKey) {
            $this->lastError = '授权文件与当前应用不匹配';
            return false;
        }
        if (!$this->verifySignature($payload)) {
            $this->lastError = '授权文件签名校验失败';
            return false;
        }
        if (!empty($payload['expireAt']) && self::parseTime($payload['expireAt']) <= time()) {
            $this->lastError = '授权已过期';
            return false;
        }

        if ($domain === '') {
            $domain = self::detectDomain();
        }
        if ($serverIp === '') {
            $serverIp = self::detectServerIp();
        }
        if ($machineId === '') {
            $machineId = self::machineId();
        }
        $domain = self::normalizeDomain($domain);
        $serverIp = self::normalizeServerIp($serverIp);

        $bind = isset($payload['bind']) && is_array($payload['bind']) ? $payload['bind'] : array();

        $bindDomains = isset($bind['domains']) ? $bind['domains'] : array();
        if (!empty($bindDomains) && !self::matchDomain($bindDomains, $domain)) {
            $this->lastError = '授权文件未绑定当前域名：' . $domain;
            return false;
        }

        $bindIps = isset($bind['ips']) ? $bind['ips'] : array();
        if (!empty($bindIps)) {
            $matched = false;
            foreach ($bindIps as $ip) {
                if ($ip !== '' && ($ip === $serverIp || $ip === $domain)) {
                    $matched = true;
                    break;
                }
            }
            if (!$matched) {
                $this->lastError = '授权文件未绑定当前服务器 IP：' . $serverIp;
                return false;
            }
        }

        $bindMachines = isset($bind['machines']) ? $bind['machines'] : array();
        if (!empty($bindMachines) && !in_array($machineId, $bindMachines, true)) {
            $this->lastError = '授权文件未绑定当前机器码：' . $machineId;
            return false;
        }

        return true;
    }

    /**
     * 完整校验：离线验签通过后按心跳周期回源，回源失败时进入宽限期。
     *
     * 调用失败时可用 getLastError() 取原因。
     *
     * @param string $licenseFile 授权文件路径或内容
     * @param array  $options     可选参数：domain / serverIp / machineId / cacheFile
     * @return bool
     */
    public function check($licenseFile, array $options = array())
    {
        $this->lastError = '';

        if (is_file($licenseFile)) {
            $content = @file_get_contents($licenseFile);
            if ($content === false) {
                $this->lastError = '授权文件读取失败：' . $licenseFile;
                return false;
            }
        } else {
            $content = $licenseFile;
        }

        $payload = self::parse($content);
        $domain = isset($options['domain']) ? $options['domain'] : '';
        $serverIp = isset($options['serverIp']) ? $options['serverIp'] : '';
        $machineId = isset($options['machineId']) ? $options['machineId'] : '';

        if (!$this->verifyOffline($payload, $domain, $serverIp, $machineId)) {
            return false;
        }

        $heartbeatDays = isset($payload['heartbeatDays']) ? (int) $payload['heartbeatDays'] : 0;
        $graceDays = isset($payload['graceDays']) ? (int) $payload['graceDays'] : 0;

        // heartbeatDays = 0 表示纯离线，签发时就不需要回源
        if ($heartbeatDays <= 0) {
            return true;
        }

        $cachePath = isset($options['cacheFile']) && $options['cacheFile'] !== ''
            ? $options['cacheFile']
            : $this->cacheFile;
        $last = $this->readHeartbeatCache($cachePath);

        $heartbeatSeconds = $heartbeatDays * 86400;
        $graceSeconds = $graceDays * 86400;
        $now = time();

        // 未到心跳窗口且仍在允许的离线区间内（含宽限期）
        if ($last > 0 && $now - $last < $heartbeatSeconds) {
            return true;
        }
        if ($this->heartbeat($payload, $content, $domain, $serverIp, $machineId)) {
            $this->writeHeartbeatCache($cachePath, $now);
            return true;
        }

        // 回源失败：宽限期内仍放行，超过宽限期才判定失效
        if ($last > 0 && $now - $last <= $heartbeatSeconds + $graceSeconds) {
            return true;
        }

        if ($this->lastError === '') {
            $this->lastError = '授权回源失败且已超出离线宽限期';
        }
        return false;
    }

    /**
     * 校验失败时以 403 终止请求，适合放在站点入口做授权守卫。
     *
     * @param string $licenseFile 授权文件路径或内容
     * @param array  $options     同 check()
     */
    public function guard($licenseFile, array $options = array(), $message = 'License invalid')
    {
        if ($this->check($licenseFile, $options)) {
            return;
        }
        http_response_code(403);
        $detail = $this->lastError !== '' ? $message . ': ' . $this->lastError : $message;
        exit($detail);
    }

    /**
     * 机器码采集：默认取主机名 + 首个非回环 MAC 地址做哈希，同一台机器保持稳定。
     *
     * @param string|null $salt 业务自定义盐值，可为空
     * @return string 32 位十六进制机器码
     */
    public static function machineId($salt = null)
    {
        $host = function_exists('php_uname') ? php_uname('n') : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '');
        $mac = '';
        foreach (array('/sbin/ifconfig', '/bin/ifconfig', '/sbin/ip', '/bin/ip') as $tool) {
            if (is_executable($tool)) {
                $mac = (string) @shell_exec($tool . ' 2>/dev/null');
                if ($mac !== '') {
                    break;
                }
            }
        }
        if ($mac === '' && is_dir('/sys/class/net')) {
            $interfaces = @scandir('/sys/class/net');
            if (is_array($interfaces)) {
                $mac = implode(',', array_values(array_diff($interfaces, array('.', '..', 'lo'))));
            }
        }
        if ($mac !== '') {
            preg_match_all('/([0-9a-f]{2}(?::|-)[0-9a-f]{2}(?:(?::|-)[0-9a-f]{2}){4})/i', $mac, $matches);
            if (!empty($matches[1])) {
                $mac = strtolower($matches[1][0]);
            }
        }
        return hash('sha256', strtolower(trim($host)) . '|' . $mac . '|' . ($salt === null ? '' : $salt));
    }

    // ==================== 内部实现 ====================

    /**
     * RSA-SHA256 验签（PKCS#1 v1.5）。
     * 规范串必须与服务端 licenseFileCanonical 逐字节一致。
     */
    private function verifySignature($payload)
    {
        $signature = isset($payload['signature']) ? trim($payload['signature']) : '';
        if ($signature === '') {
            return false;
        }
        $binary = base64_decode($signature, true);
        if ($binary === false) {
            return false;
        }
        $publicKey = openssl_pkey_get_public($this->publicKey);
        if ($publicKey === false) {
            return false;
        }
        $result = openssl_verify($this->canonical($payload), $binary, $publicKey, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    /**
     * 构造待签名规范串，字段顺序与服务端一致。
     * 列表需排序去重（PHP SORT_STRING 与 Go sort.Strings 同为字节序）。
     */
    private function canonical($payload)
    {
        $bind = isset($payload['bind']) && is_array($payload['bind']) ? $payload['bind'] : array();
        $value = function ($key) use ($payload) {
            return isset($payload[$key]) ? (string) $payload[$key] : '';
        };
        return implode("\n", array(
            'auth-pro-license-file/v1',
            $value('version'),
            $value('fileNo'),
            $value('licenseNo'),
            $value('licenseId'),
            $value('appKey'),
            $value('planName'),
            implode(',', self::normalizeBindList($bind, 'domains', true)),
            implode(',', self::normalizeBindList($bind, 'ips', false)),
            implode(',', self::normalizeBindList($bind, 'machines', false)),
            $value('heartbeatDays'),
            $value('graceDays'),
            $value('issuedAt'),
            $value('expireAt'),
        ));
    }

    /** 绑定列表规范化：去空、去重、排序，域名额外做小写与去主机头处理 */
    private static function normalizeBindList($bind, $key, $asDomain)
    {
        $values = array();
        if (isset($bind[$key]) && is_array($bind[$key])) {
            foreach ($bind[$key] as $item) {
                $item = trim((string) $item);
                if ($item === '') {
                    continue;
                }
                if ($asDomain) {
                    $item = self::normalizeDomain($item);
                } else {
                    $item = strtolower($item);
                }
                if ($item === '') {
                    continue;
                }
                $values[] = $item;
            }
        }
        $values = array_values(array_unique($values));
        sort($values, SORT_STRING);
        return $values;
    }

    /** 回源校验：HMAC-SHA256 请求签名 + JSON POST /api/license/file/verify */
    private function heartbeat($payload, $licenseContent, $domain, $serverIp, $machineId)
    {
        if ($this->baseUrl === '' || $this->appKey === '' || $this->appSecret === '') {
            $this->lastError = 'SDK 未正确配置 baseUrl / appKey / appSecret';
            return false;
        }
        if (!function_exists('curl_init')) {
            $this->lastError = 'PHP 未启用 cURL 扩展，无法完成心跳回源';
            return false;
        }

        if ($domain === '') {
            $domain = self::detectDomain();
        }
        if ($serverIp === '') {
            $serverIp = self::detectServerIp();
        }
        if ($machineId === '') {
            $machineId = self::machineId();
        }
        $domain = self::normalizeDomain($domain);
        $serverIp = self::normalizeServerIp($serverIp);

        $timestamp = time();
        $request = array(
            'appKey' => $this->appKey,
            'licenseFile' => trim($licenseContent),
            'domain' => $domain,
            'serverIp' => $serverIp,
            'machineId' => $machineId,
            'timestamp' => $timestamp,
            'signVersion' => 'v3',
            'sign' => hash_hmac(
                'sha256',
                implode("\n", array('v3', $this->appKey, $domain, $serverIp, $machineId, (string) $timestamp)),
                $this->appSecret
            ),
        );

        $ch = curl_init($this->baseUrl . '/api/license/file/verify');
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
            CURLOPT_POSTFIELDS => json_encode($request),
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeout),
        ));
        $body = curl_exec($ch);
        if ($body === false) {
            $this->lastError = '心跳回源失败：' . curl_error($ch);
            curl_close($ch);
            return false;
        }
        curl_close($ch);

        $data = json_decode($body, true);
        if (!is_array($data)) {
            $this->lastError = '心跳回源返回异常（不是合法 JSON）';
            return false;
        }
        $code = isset($data['code']) ? (int) $data['code'] : 0;
        $result = isset($data['data']['result']) ? $data['data']['result'] : '';
        if ($code === 200 && $result === 'pass') {
            return true;
        }
        $this->lastError = isset($data['msg']) && $data['msg'] !== ''
            ? (string) $data['msg']
            : '授权校验未通过';
        return false;
    }

    private function readHeartbeatCache($path)
    {
        if (!is_file($path)) {
            return 0;
        }
        $raw = @file_get_contents($path);
        $data = $raw === false ? null : json_decode($raw, true);
        return is_array($data) && isset($data['lastSeen']) ? (int) $data['lastSeen'] : 0;
    }

    private function writeHeartbeatCache($path, $time)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @file_put_contents($path, json_encode(array(
            'lastSeen' => $time,
            'fileNo' => '',
            'updatedAt' => date('c', $time),
        )));
    }

    /** 域名匹配，支持 *.example.com 泛域名 */
    private static function matchDomain($patterns, $domain)
    {
        if ($domain === '') {
            return false;
        }
        foreach ($patterns as $pattern) {
            $pattern = self::normalizeDomain($pattern);
            if ($pattern === '') {
                continue;
            }
            if (strpos($pattern, '*.') === 0) {
                $suffix = substr($pattern, 1);
                if (substr($domain, -strlen($suffix)) === $suffix && $domain !== substr($pattern, 2)) {
                    return true;
                }
                continue;
            }
            if ($pattern === $domain) {
                return true;
            }
        }
        return false;
    }

    /** 解析服务端签发的 RFC3339 UTC 时间 */
    private static function parseTime($value)
    {
        $time = strtotime((string) $value);
        return $time === false ? 0 : $time;
    }

    /** @return string 当前访问域名 */
    private static function detectDomain()
    {
        return isset($_SERVER['HTTP_HOST']) ? trim($_SERVER['HTTP_HOST']) : '';
    }

    /** @return string 当前服务器 IP */
    private static function detectServerIp()
    {
        return isset($_SERVER['SERVER_ADDR']) ? trim($_SERVER['SERVER_ADDR']) : '';
    }

    /** 与服务端 normalizeLicenseDomain 对齐 */
    public static function normalizeDomain($domain)
    {
        $value = strtolower(trim((string) $domain));
        if (strpos($value, 'http://') === 0) {
            $value = substr($value, 7);
        } elseif (strpos($value, 'https://') === 0) {
            $value = substr($value, 8);
        }
        $slash = strpos($value, '/');
        if ($slash !== false) {
            $value = substr($value, 0, $slash);
        }
        if (preg_match('/^\[([^\]]+)\]:\d+$/', $value, $matches)) {
            $value = $matches[1];
        } elseif (substr_count($value, ':') === 1 && preg_match('/^([^:]+):\d+$/', $value, $matches)) {
            $value = $matches[1];
        }
        $value = rtrim($value, '.');
        $value = trim($value, '[]');
        if ($value === '') {
            return '';
        }
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return self::canonicalIp($value);
        }
        return $value;
    }

    /** 与服务端 normalizeLicenseServerIP 对齐 */
    public static function normalizeServerIp($ip)
    {
        $value = trim((string) $ip);
        $zone = strrpos($value, '%');
        if ($zone !== false && $zone > 0) {
            $value = substr($value, 0, $zone);
        }
        $value = trim($value, '[]');
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return self::canonicalIp($value);
        }
        return '';
    }

    private static function canonicalIp($ip)
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return $ip;
        }
        $out = @inet_ntop($packed);
        return $out === false ? $ip : $out;
    }
}
