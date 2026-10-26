// Package licensefile 提供 AuthPro License 文件授权校验能力。
//
// 授权文件由授权服务端使用应用 RSA-2048 私钥签发，本 SDK 仅持有公钥即可本地验签，
// 无需每次启动都联网；仅在心跳周期到达时回源一次，用于同步吊销与黑名单状态。
//
// 用法:
//
//	client, err := licensefile.New("https://license.example.com", appKey, appSecret, publicKeyPEM)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := client.CheckFile("license.lic", licensefile.Context{Domain: "example.com"}); err != nil {
//	    log.Fatalf("授权无效: %v", err)
//	}
package licensefile

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	beginLine = "-----BEGIN AUTH PRO LICENSE FILE-----"
	endLine   = "-----END AUTH PRO LICENSE FILE-----"
	signV3    = "v3"
)

// Payload 授权文件内容，字段与服务端签发结构一一对应。
type Payload struct {
	Version       int    `json:"version"`
	FileNo        string `json:"fileNo"`
	LicenseNo     string `json:"licenseNo"`
	LicenseId     int64  `json:"licenseId"`
	AppKey        string `json:"appKey"`
	PlanName      string `json:"planName"`
	Bind          Bind   `json:"bind"`
	HeartbeatDays int    `json:"heartbeatDays"`
	GraceDays     int    `json:"graceDays"`
	IssuedAt      string `json:"issuedAt"`
	ExpireAt      string `json:"expireAt"`
	Signature     string `json:"signature"`
}

// Bind 授权文件的运行环境绑定，三类均为可选，空表示不限制。
type Bind struct {
	Domains  []string `json:"domains"`
	Ips      []string `json:"ips"`
	Machines []string `json:"machines"`
}

// Context 当前运行环境，留空字段会自动采集（域名/IP 需要 HTTP 场景才可用）。
type Context struct {
	Domain    string
	ServerIP  string
	MachineID string
}

// Client License 文件校验客户端。
type Client struct {
	BaseURL      string
	AppKey       string
	AppSecret    string
	PublicKeyPEM string
	Timeout      time.Duration
	CacheFile    string

	publicKey *rsa.PublicKey
}

// New 创建客户端并解析应用公钥（公钥由授权后台「应用管理」提供）。
func New(baseURL, appKey, appSecret, publicKeyPEM string) (*Client, error) {
	client := &Client{
		BaseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		AppKey:       strings.TrimSpace(appKey),
		AppSecret:    appSecret,
		PublicKeyPEM: publicKeyPEM,
		Timeout:      8 * time.Second,
		CacheFile:    defaultCacheFile(appKey),
	}
	if err := client.loadPublicKey(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) loadPublicKey() error {
	block, _ := pem.Decode([]byte(c.PublicKeyPEM))
	if block == nil {
		return errors.New("公钥解析失败：不是合法的 PEM 格式")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("公钥不是 RSA 公钥")
	}
	c.publicKey = rsaKey
	return nil
}

// Parse 解析授权文件，兼容装甲格式与裸 JSON。
func Parse(content []byte) (*Payload, error) {
	raw := strings.TrimSpace(string(content))
	if raw == "" {
		return nil, errors.New("授权文件内容为空")
	}
	if strings.Contains(raw, beginLine) {
		inner := strings.ReplaceAll(strings.ReplaceAll(raw, beginLine, ""), endLine, "")
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(inner), ""))
		if err != nil {
			return nil, fmt.Errorf("授权文件 base64 解码失败: %w", err)
		}
		raw = string(decoded)
	}
	var payload Payload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("授权文件 JSON 解析失败: %w", err)
	}
	return &payload, nil
}

// VerifyOffline 离线校验：验签 + 有效期 + 运行环境绑定，完全不联网。
func (c *Client) VerifyOffline(payload *Payload, ctx Context) error {
	if payload == nil {
		return errors.New("授权文件解析失败")
	}
	if payload.AppKey != "" && payload.AppKey != c.AppKey {
		return errors.New("授权文件与当前应用不匹配")
	}
	if err := c.verifySignature(payload); err != nil {
		return err
	}
	if payload.ExpireAt != "" {
		expireAt, err := time.Parse(time.RFC3339, payload.ExpireAt)
		if err != nil {
			return fmt.Errorf("授权文件到期时间格式错误: %w", err)
		}
		if !time.Now().Before(expireAt) {
			return errors.New("授权已过期")
		}
	}

	if err := c.checkBindings(payload, fillContext(ctx)); err != nil {
		return err
	}
	return nil
}

// CheckFile 读取授权文件并完成完整校验（离线验签 + 心跳回源）。
func (c *Client) CheckFile(path string, ctx Context) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取授权文件失败: %w", err)
	}
	return c.Check(string(content), ctx)
}

// Check 完整校验：离线验签通过后按心跳周期回源，回源失败时进入宽限期。
func (c *Client) Check(content string, ctx Context) error {
	payload, err := Parse([]byte(content))
	if err != nil {
		return err
	}
	if err := c.VerifyOffline(payload, ctx); err != nil {
		return err
	}

	// heartbeatDays = 0 表示纯离线授权，无需回源
	if payload.HeartbeatDays <= 0 {
		return nil
	}

	full := fillContext(ctx)
	heartbeat := time.Duration(payload.HeartbeatDays) * 24 * time.Hour
	grace := time.Duration(payload.GraceDays) * 24 * time.Hour

	last := c.readHeartbeat()
	now := time.Now()
	if !last.IsZero() && now.Sub(last) < heartbeat {
		return nil
	}
	if err := c.heartbeat(payload, content, full); err != nil {
		// 回源失败：宽限期内仍放行，超时才算失效
		if !last.IsZero() && now.Sub(last) <= heartbeat+grace {
			return nil
		}
		return err
	}
	c.writeHeartbeat(now)
	return nil
}

// heartbeat 按 v3 签名请求服务端校验接口。
func (c *Client) heartbeat(payload *Payload, content string, ctx Context) error {
	if c.BaseURL == "" || c.AppKey == "" || c.AppSecret == "" {
		return errors.New("SDK 未正确配置 baseUrl / appKey / appSecret")
	}
	timestamp := time.Now().Unix()
	canonical := strings.Join([]string{
		signV3, c.AppKey, ctx.Domain, ctx.ServerIP, ctx.MachineID, int64ToString(timestamp),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(c.AppSecret))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	body, err := json.Marshal(map[string]any{
		"appKey":      c.AppKey,
		"licenseFile": strings.TrimSpace(content),
		"domain":      ctx.Domain,
		"serverIp":    ctx.ServerIP,
		"machineId":   ctx.MachineID,
		"timestamp":   timestamp,
		"signVersion": signV3,
		"sign":        signature,
	})
	if err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/license/file/verify", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.Timeout}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("心跳回源失败: %w", err)
	}
	defer response.Body.Close()

	raw, _ := io.ReadAll(response.Body)
	var decoded struct {
		Code int `json:"code"`
		Data struct {
			Result string `json:"result"`
		} `json:"data"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return errors.New("心跳回源返回异常（不是合法 JSON）")
	}
	if decoded.Code == 200 && decoded.Data.Result == "pass" {
		return nil
	}
	if decoded.Msg != "" {
		return errors.New(decoded.Msg)
	}
	return errors.New("授权校验未通过")
}

// verifySignature RSA-SHA256(PKCS#1 v1.5) 验签，规范串需与服务端逐字节一致。
func (c *Client) verifySignature(payload *Payload) error {
	if c.publicKey == nil {
		return errors.New("SDK 未配置应用公钥")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload.Signature))
	if err != nil {
		return fmt.Errorf("签名解码失败: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical(payload)))
	if err := rsa.VerifyPKCS1v15(c.publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return errors.New("授权文件签名校验失败")
	}
	return nil
}

// canonical 构造待签名规范串，字段顺序与服务端 licenseFileCanonical 保持一致。
func canonical(payload *Payload) string {
	return strings.Join([]string{
		"auth-pro-license-file/v1",
		strconv.Itoa(payload.Version),
		payload.FileNo,
		payload.LicenseNo,
		strconv.FormatInt(payload.LicenseId, 10),
		payload.AppKey,
		payload.PlanName,
		strings.Join(normalizeList(payload.Bind.Domains, true), ","),
		strings.Join(normalizeList(payload.Bind.Ips, false), ","),
		strings.Join(normalizeList(payload.Bind.Machines, false), ","),
		strconv.Itoa(payload.HeartbeatDays),
		strconv.Itoa(payload.GraceDays),
		payload.IssuedAt,
		payload.ExpireAt,
	}, "\n")
}

// checkBindings 每个非空绑定维度都必须命中。
func (c *Client) checkBindings(payload *Payload, ctx Context) error {
	if len(payload.Bind.Domains) > 0 {
		matched := false
		for _, item := range payload.Bind.Domains {
			if item != "" && wildcardMatch(item, ctx.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("授权文件未绑定当前域名: %s", ctx.Domain)
		}
	}
	if len(payload.Bind.Ips) > 0 {
		matched := false
		for _, item := range payload.Bind.Ips {
			if item != "" && (item == ctx.ServerIP || item == ctx.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("授权文件未绑定当前服务器 IP: %s", ctx.ServerIP)
		}
	}
	if len(payload.Bind.Machines) > 0 {
		matched := false
		for _, item := range payload.Bind.Machines {
			if item == ctx.MachineID {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("授权文件未绑定当前机器码: %s", ctx.MachineID)
		}
	}
	return nil
}

// MachineID 采集机器指纹：主机名 + 首个非回环 MAC 地址的 SHA-256，同机器保持稳定。
func MachineID() string {
	hostname, _ := os.Hostname()
	var mac string
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			address := strings.TrimSpace(iface.HardwareAddr.String())
			if address == "" || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			mac = strings.ToLower(address)
			break
		}
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(hostname)) + "|" + mac))
	return hex.EncodeToString(sum[:])
}

// fillContext 补齐运行环境信息。
func fillContext(ctx Context) Context {
	if ctx.Domain == "" {
		ctx.Domain = detectDomain()
	}
	if ctx.ServerIP == "" {
		ctx.ServerIP = detectServerIP()
	}
	if ctx.MachineID == "" {
		ctx.MachineID = MachineID()
	}
	ctx.Domain = normalizeTarget(ctx.Domain)
	ctx.ServerIP = normalizeIP(ctx.ServerIP)
	return ctx
}

type heartbeatCache struct {
	LastSeen string `json:"lastSeen"`
}

func (c *Client) readHeartbeat() time.Time {
	path := c.CacheFile
	if path == "" {
		path = defaultCacheFile(c.AppKey)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	var cache heartbeatCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, cache.LastSeen)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func (c *Client) writeHeartbeat(at time.Time) {
	path := c.CacheFile
	if path == "" {
		path = defaultCacheFile(c.AppKey)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	raw, _ := json.Marshal(heartbeatCache{LastSeen: at.UTC().Format(time.RFC3339)})
	_ = os.WriteFile(path, raw, 0o600)
}

func defaultCacheFile(appKey string) string {
	sum := sha256.Sum256([]byte(appKey))
	return filepath.Join(os.TempDir(), fmt.Sprintf("authpro-license-%s.json", hex.EncodeToString(sum[:])[:12]))
}

func detectDomain() string {
	if host := os.Getenv("HTTP_HOST"); host != "" {
		return host
	}
	hostname, _ := os.Hostname()
	return hostname
}

func detectServerIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}

// normalizeList 去空、去重、排序（与服务端 Go 的 sort.Strings 同为字节序）。
func normalizeList(values []string, asDomain bool) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if asDomain {
			value = normalizeTarget(value)
		} else {
			value = strings.ToLower(value)
		}
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeTarget(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return value
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.LastIndex(value, "%"); idx > 0 {
		value = value[:idx]
	}
	value = strings.Trim(value, "[]")
	if net.ParseIP(value) == nil {
		return ""
	}
	if parsed := net.ParseIP(value); parsed.To4() != nil {
		return parsed.To4().String()
	}
	return net.ParseIP(value).String()
}

func wildcardMatch(pattern, domain string) bool {
	pattern = normalizeTarget(pattern)
	domain = normalizeTarget(domain)
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == domain
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(domain, suffix) && domain != strings.TrimPrefix(pattern, "*.")
}

func int64ToString(value int64) string {
	return strconv.FormatInt(value, 10)
}
