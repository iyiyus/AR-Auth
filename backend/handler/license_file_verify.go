package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"auto_pro/config"

	"github.com/gin-gonic/gin"
)

type licenseFileVerifyRequest struct {
	AppKey      string `json:"appKey" binding:"required"`
	LicenseFile string `json:"licenseFile"`
	Domain      string `json:"domain"`
	ServerIP    string `json:"serverIp"`
	MachineId   string `json:"machineId"`
	Timestamp   int64  `json:"timestamp" binding:"required"`
	SignVersion string `json:"signVersion"`
	Sign        string `json:"sign" binding:"required"`
}

// LicenseFileVerify 授权文件校验（公开接口，供 SDK 心跳回源）。
// 客户端平时用公钥离线验签，按心跳周期调用本接口完成吊销/黑名单同步。
func LicenseFileVerify(c *gin.Context) {
	var req licenseFileVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "参数错误", "data": gin.H{"result": "fail", "reason": "bad_request"}})
		return
	}

	req.AppKey = strings.TrimSpace(req.AppKey)
	req.Domain = normalizeLicenseDomain(req.Domain)
	req.ServerIP = normalizeLicenseServerIP(req.ServerIP)
	req.MachineId = strings.ToLower(strings.TrimSpace(req.MachineId))
	req.Sign = strings.ToLower(strings.TrimSpace(req.Sign))

	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "系统未配置", "data": gin.H{"result": "fail", "reason": "system_not_configured"}})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败", "data": gin.H{"result": "fail", "reason": "schema_init_failed"}})
		return
	}

	var appID int64
	var appName, appSecret, publicKey string
	if err := db.QueryRow(`
		SELECT id, app_name, app_secret, COALESCE(license_public_key, '')
		FROM apps WHERE app_key = ? AND enabled = 1
	`, req.AppKey).Scan(&appID, &appName, &appSecret, &publicKey); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "应用不存在或已禁用", "data": gin.H{"result": "fail", "reason": "app_not_found"}})
		return
	}

	if req.Timestamp <= 0 || absInt64(time.Now().Unix()-req.Timestamp) > 600 {
		writeVerifyLog(db, sql.NullInt64{}, appID, req.Domain, req.ServerIP, c.ClientIP(), "fail", "invalid_timestamp", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "请求已过期", "data": gin.H{"result": "fail", "reason": "invalid_timestamp"}})
		return
	}

	if strings.TrimSpace(req.LicenseFile) == "" {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件内容不能为空", "data": gin.H{"result": "fail", "reason": "empty_license_file"}})
		return
	}

	if !licenseFileRequestSignValid(req, appSecret) {
		writeVerifyLog(db, sql.NullInt64{}, appID, req.Domain, req.ServerIP, c.ClientIP(), "fail", "invalid_sign", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "签名错误", "data": gin.H{"result": "fail", "reason": "invalid_sign"}})
		return
	}

	payload, err := parseLicenseFileContent(req.LicenseFile)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件格式不正确", "data": gin.H{"result": "fail", "reason": "invalid_license_file"}})
		return
	}
	if payload.AppKey != req.AppKey {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件与应用不匹配", "data": gin.H{"result": "fail", "reason": "app_mismatch"}})
		return
	}
	if !licenseFileVerifySignature(payload, publicKey) {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件签名校验失败", "data": gin.H{"result": "fail", "reason": "license_file_signature_invalid"}})
		return
	}

	var fileID, fileLicenseID, fileAppID int64
	var heartbeatDays, graceDays int
	var fileStatus string
	var fileExpireAt sql.NullTime
	if err := db.QueryRow(`
		SELECT id, license_id, app_id, status, heartbeat_days, grace_days, expire_at
		FROM license_files WHERE file_no = ?
	`, payload.FileNo).Scan(&fileID, &fileLicenseID, &fileAppID, &fileStatus, &heartbeatDays, &graceDays, &fileExpireAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件不存在", "data": gin.H{"result": "fail", "reason": "license_file_not_found"}})
		} else {
			c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "查询授权文件失败", "data": gin.H{"result": "fail", "reason": "query_failed"}})
		}
		return
	}
	if fileAppID != appID {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件与应用不匹配", "data": gin.H{"result": "fail", "reason": "app_mismatch"}})
		return
	}
	if fileStatus == "revoked" {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件已吊销", "data": gin.H{"result": "fail", "reason": "license_file_revoked"}})
		return
	}

	var licenseID int64
	var planName, licenseStatus string
	var expiredAt sql.NullTime
	if err := db.QueryRow(`
		SELECT l.id, COALESCE(p.name, ''), l.status, l.expired_at
		FROM licenses l
		LEFT JOIN license_plans p ON p.id = l.plan_id AND p.app_id = l.app_id
		WHERE l.id = ? AND l.app_id = ?
	`, fileLicenseID, appID).Scan(&licenseID, &planName, &licenseStatus, &expiredAt); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权无效", "data": gin.H{"result": "fail", "reason": "license_not_found"}})
		return
	}

	if isLicenseTargetBlacklisted(db, appID, req.Domain, req.ServerIP) {
		writeVerifyLog(db, sql.NullInt64{Int64: licenseID, Valid: true}, appID, req.Domain, req.ServerIP, c.ClientIP(), "blacklisted", "target_blacklisted", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权目标已被拉黑", "data": gin.H{"result": "blacklisted", "reason": "target_blacklisted"}})
		return
	}

	if licenseStatus == "revoked" {
		writeVerifyLog(db, sql.NullInt64{Int64: licenseID, Valid: true}, appID, req.Domain, req.ServerIP, c.ClientIP(), "fail", "license_revoked", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权已吊销", "data": gin.H{"result": "fail", "reason": "license_revoked"}})
		return
	}
	if licenseStatus == "expired" || (expiredAt.Valid && !expiredAt.Time.After(time.Now())) {
		writeVerifyLog(db, sql.NullInt64{Int64: licenseID, Valid: true}, appID, req.Domain, req.ServerIP, c.ClientIP(), "expired", "license_expired", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权已过期", "data": gin.H{"result": "expired", "reason": "license_expired"}})
		return
	}

	if !licenseFileBindMatched(payload, req.Domain, req.ServerIP, req.MachineId) {
		writeVerifyLog(db, sql.NullInt64{Int64: licenseID, Valid: true}, appID, req.Domain, req.ServerIP, c.ClientIP(), "fail", "license_file_bind_mismatch", c.GetHeader("User-Agent"))
		c.JSON(http.StatusOK, gin.H{"code": 403, "msg": "授权文件与当前运行环境不匹配", "data": gin.H{"result": "fail", "reason": "license_file_bind_mismatch"}})
		return
	}

	writeVerifyLog(db, sql.NullInt64{Int64: licenseID, Valid: true}, appID, req.Domain, req.ServerIP, c.ClientIP(), "pass", "", c.GetHeader("User-Agent"))
	_, _ = db.Exec(`
		UPDATE license_files
		SET last_seen_at = NOW(), last_domain = ?, last_ip = ?, last_machine = ?
		WHERE id = ?
	`, req.Domain, req.ServerIP, req.MachineId, fileID)

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "授权有效",
		"data": gin.H{
			"result":        "pass",
			"appName":       appName,
			"planName":      planName,
			"fileNo":        payload.FileNo,
			"type":          "file",
			"expireAt":      formatVerifyExpireAt(expiredAt),
			"heartbeatDays": heartbeatDays,
			"graceDays":     graceDays,
			"serverTime":    time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// licenseFileRequestSignValid v3 请求签名：HMAC-SHA256(appSecret, "v3\nappKey\ndomain\nserverIp\nmachineId\ntimestamp")
func licenseFileRequestSignValid(req licenseFileVerifyRequest, appSecret string) bool {
	version := strings.ToLower(strings.TrimSpace(req.SignVersion))
	if version != "" && version != licenseSignVersionV3 {
		return false
	}
	canonical := strings.Join([]string{
		licenseSignVersionV3,
		req.AppKey,
		req.Domain,
		req.ServerIP,
		req.MachineId,
		int64ToString(req.Timestamp),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(canonical))
	// 请求签名以小写十六进制传输，比对前需同样编码
	return hmac.Equal([]byte(req.Sign), []byte(hex.EncodeToString(mac.Sum(nil))))
}

// licenseFileBindMatched 每个非空绑定维度都必须命中，空值视为不通过。
func licenseFileBindMatched(payload licenseFilePayload, domain, serverIP, machineID string) bool {
	if len(payload.Bind.Domains) > 0 && !licenseFileMatchDomain(payload.Bind.Domains, domain) {
		return false
	}
	if len(payload.Bind.Ips) > 0 {
		matched := false
		for _, item := range payload.Bind.Ips {
			if item != "" && (item == serverIP || item == domain) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(payload.Bind.Machines) > 0 && !containsLicenseFileValue(payload.Bind.Machines, machineID) {
		return false
	}
	return true
}

func licenseFileMatchDomain(list []string, domain string) bool {
	if domain == "" {
		return false
	}
	for _, item := range list {
		if item != "" && wildcardDomainMatch(item, domain) {
			return true
		}
	}
	return false
}

func containsLicenseFileValue(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
