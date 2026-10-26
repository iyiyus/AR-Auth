package handler

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"auto_pro/config"

	"github.com/gin-gonic/gin"
)

// License 文件授权：服务端用应用级 RSA-2048 私钥签发离线授权文件，
// SDK 仅持有公钥即可本地验签，并按心跳周期回源完成吊销/黑名单同步。

const (
	licenseFileBeginLine = "-----BEGIN AUTH PRO LICENSE FILE-----"
	licenseFileEndLine   = "-----END AUTH PRO LICENSE FILE-----"
	licenseFileVersion   = 1
	licenseSignVersionV3 = "v3"
)

type licenseFilePayload struct {
	Version   int    `json:"version"`
	FileNo    string `json:"fileNo"`
	LicenseNo string `json:"licenseNo"`
	LicenseId int64  `json:"licenseId"`
	AppKey    string `json:"appKey"`
	PlanName  string `json:"planName"`
	Bind      struct {
		Domains  []string `json:"domains"`
		Ips      []string `json:"ips"`
		Machines []string `json:"machines"`
	} `json:"bind"`
	HeartbeatDays int    `json:"heartbeatDays"`
	GraceDays     int    `json:"graceDays"`
	IssuedAt      string `json:"issuedAt"`
	ExpireAt      string `json:"expireAt"`
	Signature     string `json:"signature"`
}

type licenseFileIssueRequest struct {
	LicenseID     int64    `json:"licenseId"`
	Domains       []string `json:"domains"`
	Ips           []string `json:"ips"`
	MachineIds    []string `json:"machineIds"`
	HeartbeatDays int      `json:"heartbeatDays"`
	GraceDays     int      `json:"graceDays"`
}

// ==================== 签名与文件格式 ====================

// licenseFileCanonical 构造待签名规范串，字段顺序与排序规则 SDK 侧需严格一致。
func licenseFileCanonical(payload licenseFilePayload) string {
	return strings.Join([]string{
		"auth-pro-license-file/v1",
		strconv.Itoa(payload.Version),
		payload.FileNo,
		payload.LicenseNo,
		strconv.FormatInt(payload.LicenseId, 10),
		payload.AppKey,
		payload.PlanName,
		strings.Join(normalizedBindList(payload.Bind.Domains, true), ","),
		strings.Join(normalizedBindList(payload.Bind.Ips, false), ","),
		strings.Join(normalizedBindList(payload.Bind.Machines, false), ","),
		strconv.Itoa(payload.HeartbeatDays),
		strconv.Itoa(payload.GraceDays),
		payload.IssuedAt,
		payload.ExpireAt,
	}, "\n")
}

func normalizedBindList(values []string, asDomain bool) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if asDomain {
			value = normalizeLicenseTarget(value)
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

func licenseFileSign(payload licenseFilePayload, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("私钥解析失败")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(licenseFileCanonical(payload)))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func licenseFileVerifySignature(payload licenseFilePayload, publicKeyPEM string) bool {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload.Signature))
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(licenseFileCanonical(payload)))
	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature) == nil
}

// licenseFileArmor 将授权文件 JSON 包装为便于传输与落盘的装甲文本。
func licenseFileArmor(content []byte) string {
	encoded := base64.StdEncoding.EncodeToString(content)
	var builder strings.Builder
	builder.WriteString(licenseFileBeginLine + "\n")
	for len(encoded) > 0 {
		size := 72
		if size > len(encoded) {
			size = len(encoded)
		}
		builder.WriteString(encoded[:size] + "\n")
		encoded = encoded[size:]
	}
	builder.WriteString(licenseFileEndLine + "\n")
	return builder.String()
}

// parseLicenseFileContent 兼容装甲格式与裸 JSON。
func parseLicenseFileContent(raw string) (licenseFilePayload, error) {
	var payload licenseFilePayload
	content := strings.TrimSpace(raw)
	if content == "" {
		return payload, errors.New("授权文件内容为空")
	}
	if strings.Contains(content, licenseFileBeginLine) {
		inner := content
		inner = strings.ReplaceAll(inner, licenseFileBeginLine, "")
		inner = strings.ReplaceAll(inner, licenseFileEndLine, "")
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(inner), ""))
		if err != nil {
			return payload, err
		}
		content = string(decoded)
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func generateLicenseFileNo() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	random := make([]byte, 8)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range random {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		random[i] = alphabet[index.Int64()]
	}
	return "LF" + time.Now().Format("20060102") + string(random), nil
}

// ==================== 应用密钥对 ====================

func ensureAppLicenseKeyPair(db *sql.DB, appID int64) (string, string, error) {
	var privateKey, publicKey sql.NullString
	if err := db.QueryRow(`
		SELECT license_private_key, license_public_key FROM apps WHERE id = ?
	`, appID).Scan(&privateKey, &publicKey); err != nil {
		return "", "", err
	}
	if privateKey.Valid && publicKey.Valid && privateKey.String != "" && publicKey.String != "" {
		return privateKey.String, publicKey.String, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	if _, err := db.Exec(`
		UPDATE apps SET license_private_key = ?, license_public_key = ?, license_key_updated_at = NOW() WHERE id = ?
	`, string(privatePEM), string(publicPEM), appID); err != nil {
		return "", "", err
	}
	return string(privatePEM), string(publicPEM), nil
}

// AdminAppLicenseKey 查看应用 License 文件公钥
func AdminAppLicenseKey(c *gin.Context) {
	appID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || appID <= 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "应用ID不正确"})
		return
	}
	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败: " + err.Error()})
		return
	}
	var publicKey sql.NullString
	var updatedAt sql.NullTime
	if err := db.QueryRow("SELECT license_public_key, license_key_updated_at FROM apps WHERE id = ?", appID).Scan(&publicKey, &updatedAt); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 404, "msg": "应用不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "", "data": gin.H{
		"publicKey":  publicKey.String,
		"hasKeyPair": publicKey.Valid && publicKey.String != "",
		"updatedAt":  formatLicenseFileTime(updatedAt),
	}})
}

// AdminAppLicenseKeyReset 轮换应用 License 文件密钥对（轮换后旧文件需重新签发）
func AdminAppLicenseKeyReset(c *gin.Context) {
	appID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || appID <= 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "应用ID不正确"})
		return
	}
	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败: " + err.Error()})
		return
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "生成密钥对失败"})
		return
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "生成公钥失败"})
		return
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if _, err := db.Exec(`
		UPDATE apps SET license_private_key = ?, license_public_key = ?, license_key_updated_at = NOW() WHERE id = ?
	`, string(privatePEM), string(publicPEM), appID); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "保存密钥对失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "密钥对已轮换，请重新签发授权文件", "data": gin.H{"publicKey": string(publicPEM)}})
}

// ==================== 签发 / 列表 / 吊销 ====================

func licenseFileOwnerCondition(actor licenseSiteActor) (string, []any) {
	if actor.Type == "admin" {
		return "l.id = ? AND l.type = 'file'", nil
	}
	return "l.id = ? AND l.type = 'file' AND l.owner_type = ? AND l.owner_id = ?", []any{actor.Type, actor.ID}
}

func licenseFileList(c *gin.Context, actor licenseSiteActor) {
	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败: " + err.Error()})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	where := []string{"1=1"}
	args := []any{}
	if actor.Type != "admin" {
		where = append(where, "l.owner_type = ? AND l.owner_id = ?")
		args = append(args, actor.Type, actor.ID)
	}
	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		where = append(where, "(lf.file_no LIKE ? OR l.license_no LIKE ? OR a.app_name LIKE ?)")
		args = append(args, "%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}
	// 用户端/代理端从路径限定所属授权，管理端可用任意筛选条件
	if pathID := strings.TrimSpace(c.Param("id")); pathID != "" {
		where = append(where, "lf.license_id = ?")
		args = append(args, pathID)
	}
	if licenseID := strings.TrimSpace(c.Query("licenseId")); licenseID != "" {
		where = append(where, "lf.license_id = ?")
		args = append(args, licenseID)
	}
	if appID := strings.TrimSpace(c.Query("appId")); appID != "" {
		where = append(where, "lf.app_id = ?")
		args = append(args, appID)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		where = append(where, "lf.status = ?")
		args = append(args, status)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int64
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM license_files lf
		LEFT JOIN licenses l ON l.id = lf.license_id
		LEFT JOIN apps a ON a.id = lf.app_id
		WHERE `+whereSQL, args...).Scan(&total); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "查询失败: " + err.Error()})
		return
	}

	listArgs := append(args, pageSize, (page-1)*pageSize)
	rows, err := db.Query(`
		SELECT lf.id, lf.file_no, lf.license_id, COALESCE(l.license_no, '') AS license_no,
		       lf.app_id, COALESCE(a.app_name, '') AS app_name,
		       COALESCE(p.name, '') AS plan_name,
		       lf.bind_domains, lf.bind_ips, lf.bind_machines,
		       lf.heartbeat_days, lf.grace_days, lf.status, lf.revoke_reason,
		       lf.expire_at, lf.last_seen_at, lf.last_domain, lf.last_ip, lf.last_machine,
		       lf.created_by, lf.created_at
		FROM license_files lf
		LEFT JOIN licenses l ON l.id = lf.license_id
		LEFT JOIN apps a ON a.id = lf.app_id
		LEFT JOIN license_plans p ON p.id = l.plan_id AND p.app_id = l.app_id
		WHERE `+whereSQL+`
		ORDER BY lf.created_at DESC, lf.id DESC
		LIMIT ? OFFSET ?
	`, listArgs...)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "查询失败: " + err.Error()})
		return
	}
	defer rows.Close()

	list := make([]gin.H, 0)
	for rows.Next() {
		var id, licenseID, appID int64
		var fileNo, licenseNo, appName, planName, status, revokeReason, createdBy string
		var bindDomains, bindIps, bindMachines sql.NullString
		var heartbeatDays, graceDays int
		var expireAt, lastSeenAt, createdAt sql.NullTime
		var lastDomain, lastIP, lastMachine string
		if err := rows.Scan(
			&id, &fileNo, &licenseID, &licenseNo, &appID, &appName, &planName,
			&bindDomains, &bindIps, &bindMachines,
			&heartbeatDays, &graceDays, &status, &revokeReason,
			&expireAt, &lastSeenAt, &lastDomain, &lastIP, &lastMachine,
			&createdBy, &createdAt,
		); err != nil {
			c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "读取失败"})
			return
		}
		list = append(list, gin.H{
			"id":            id,
			"fileNo":        fileNo,
			"licenseId":     licenseID,
			"licenseNo":     licenseNo,
			"appId":         appID,
			"appName":       appName,
			"planName":      planName,
			"domains":       decodeBindList(bindDomains),
			"ips":           decodeBindList(bindIps),
			"machines":      decodeBindList(bindMachines),
			"heartbeatDays": heartbeatDays,
			"graceDays":     graceDays,
			"status":        status,
			"revokeReason":  revokeReason,
			"expireAt":      formatLicenseFileTime(expireAt),
			"lastSeenAt":    formatLicenseFileTime(lastSeenAt),
			"lastDomain":    lastDomain,
			"lastIp":        lastIP,
			"lastMachine":   lastMachine,
			"createdBy":     createdBy,
			"createdAt":     formatLicenseFileTime(sql.NullTime{Time: createdAt.Time, Valid: createdAt.Valid}),
		})
	}

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "", "data": gin.H{"list": list, "total": total}})
}

func licenseFileIssue(c *gin.Context, actor licenseSiteActor) {
	var req licenseFileIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "参数错误"})
		return
	}
	// 用户端/代理端路由形如 /licenses/:id/files，管理端由请求体指定授权
	if pathID := strings.TrimSpace(c.Param("id")); pathID != "" {
		if parsed, err := strconv.ParseInt(pathID, 10, 64); err == nil && parsed > 0 {
			req.LicenseID = parsed
		}
	}
	if req.LicenseID <= 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "请选择要签发的授权"})
		return
	}

	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败: " + err.Error()})
		return
	}

	condition, ownerArgs := licenseFileOwnerCondition(actor)
	args := append([]any{req.LicenseID}, ownerArgs...)
	var licenseNo string
	var appID int64
	var planName string
	var appKey string
	var appName string
	var status string
	var expiredAt sql.NullTime
	if err := db.QueryRow(`
		SELECT l.license_no, l.app_id, COALESCE(p.name, ''), a.app_key, a.app_name, l.status, l.expired_at
		FROM licenses l
		JOIN apps a ON a.id = l.app_id AND a.enabled = 1
		LEFT JOIN license_plans p ON p.id = l.plan_id AND p.app_id = l.app_id
		WHERE `+condition, args...).Scan(&licenseNo, &appID, &planName, &appKey, &appName, &status, &expiredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, gin.H{"code": 404, "msg": "授权不存在、不是文件授权类型或无权访问"})
		} else {
			c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "查询授权失败"})
		}
		return
	}
	if status == "revoked" {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "授权已吊销，无法签发授权文件"})
		return
	}

	privateKey, publicKey, err := ensureAppLicenseKeyPair(db, appID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "获取应用签名密钥失败: " + err.Error()})
		return
	}

	domains := normalizedBindList(req.Domains, true)
	ips := normalizedBindList(req.Ips, false)
	machines := normalizedBindList(req.MachineIds, false)
	if len(domains) == 0 && len(ips) == 0 && len(machines) == 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "请至少绑定域名、服务器IP或机器码中的一种"})
		return
	}
	heartbeatDays := req.HeartbeatDays
	if heartbeatDays <= 0 {
		heartbeatDays = 30
	}
	graceDays := req.GraceDays
	if graceDays < 0 {
		graceDays = 0
	}

	fileNo, err := generateLicenseFileNo()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "生成文件编号失败"})
		return
	}

	var payload licenseFilePayload
	payload.Version = licenseFileVersion
	payload.FileNo = fileNo
	payload.LicenseNo = licenseNo
	payload.LicenseId = req.LicenseID
	payload.AppKey = appKey
	payload.PlanName = planName
	payload.Bind.Domains = domains
	payload.Bind.Ips = ips
	payload.Bind.Machines = machines
	payload.HeartbeatDays = heartbeatDays
	payload.GraceDays = graceDays
	payload.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	if expiredAt.Valid {
		payload.ExpireAt = expiredAt.Time.UTC().Format(time.RFC3339)
	}

	signature, err := licenseFileSign(payload, privateKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "签名失败: " + err.Error()})
		return
	}
	payload.Signature = signature

	content, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "生成授权文件失败"})
		return
	}

	if _, err := db.Exec(`
		INSERT INTO license_files
		(license_id, app_id, file_no, bind_domains, bind_ips, bind_machines,
		 heartbeat_days, grace_days, status, expire_at, payload, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
	`, req.LicenseID, appID, fileNo, encodeBindList(domains), encodeBindList(ips), encodeBindList(machines),
		heartbeatDays, graceDays, expiredAt, string(content), actor.Type); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "保存授权文件失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "授权文件已生成", "data": gin.H{
		"fileNo":    fileNo,
		"fileName":  fmt.Sprintf("license-%s-%s.lic", appKey, fileNo),
		"appName":   appName,
		"appKey":    appKey,
		"publicKey": publicKey,
		"content":   licenseFileArmor(content),
	}})
}

func licenseFileDownload(c *gin.Context, actor licenseSiteActor) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "文件ID不正确"})
		return
	}
	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}

	row, ok := loadLicenseFileForActor(db, id, actor)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"code": 404, "msg": "授权文件不存在或无权访问"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", row.FileName))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(licenseFileArmor([]byte(row.Payload))))
}

func licenseFileRevoke(c *gin.Context, actor licenseSiteActor) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusOK, gin.H{"code": 400, "msg": "文件ID不正确"})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	db, err := config.DB()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "数据库连接失败"})
		return
	}
	if err := EnsureLicenseFileSchema(db); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "初始化授权文件结构失败: " + err.Error()})
		return
	}

	var fileNo string
	if err := db.QueryRow(`
		SELECT lf.file_no
		FROM license_files lf
		JOIN licenses l ON l.id = lf.license_id
		WHERE lf.id = ? AND lf.status = 'active' `+licenseFileScopeCondition(actor),
		append([]any{id}, licenseFileScopeArgs(actor)...)...).Scan(&fileNo); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, gin.H{"code": 404, "msg": "授权文件不存在、已吊销或无权访问"})
		} else {
			c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "查询授权文件失败"})
		}
		return
	}

	if _, err := db.Exec(`
		UPDATE license_files SET status = 'revoked', revoked_at = NOW(), revoke_reason = ? WHERE id = ?
	`, strings.TrimSpace(body.Reason), id); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 500, "msg": "吊销失败: " + err.Error()})
		return
	}
	_, _ = db.Exec(`
		INSERT INTO operation_logs
		(operator_type, operator_id, action, target_type, target_id, detail, ip)
		VALUES (?, ?, 'license_file_revoke', 'license_file', ?, JSON_OBJECT('reason', ?), ?)
	`, actor.Type, actor.ID, id, strings.TrimSpace(body.Reason), c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "授权文件已吊销，客户端下次回源后失效"})
}

type licenseFileRow struct {
	ID       int64
	FileName string
	Payload  string
}

func loadLicenseFileForActor(db *sql.DB, id int64, actor licenseSiteActor) (licenseFileRow, bool) {
	var row licenseFileRow
	var fileNo, payload, appKey string
	err := db.QueryRow(`
		SELECT lf.id, lf.file_no, lf.payload, COALESCE(a.app_key, '')
		FROM license_files lf
		JOIN licenses l ON l.id = lf.license_id
		LEFT JOIN apps a ON a.id = lf.app_id
		WHERE lf.id = ? `+licenseFileScopeCondition(actor),
		append([]any{id}, licenseFileScopeArgs(actor)...)...).Scan(&row.ID, &fileNo, &payload, &appKey)
	if err != nil {
		return row, false
	}
	row.Payload = payload
	row.FileName = fmt.Sprintf("license-%s-%s.lic", appKey, fileNo)
	return row, true
}

func licenseFileScopeCondition(actor licenseSiteActor) string {
	if actor.Type == "admin" {
		return ""
	}
	return "AND l.owner_type = ? AND l.owner_id = ?"
}

func licenseFileScopeArgs(actor licenseSiteActor) []any {
	if actor.Type == "admin" {
		return nil
	}
	return []any{actor.Type, actor.ID}
}

func encodeBindList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func decodeBindList(value sql.NullString) []string {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return []string{}
	}
	var list []string
	if err := json.Unmarshal([]byte(value.String), &list); err != nil {
		return []string{}
	}
	return list
}

func formatLicenseFileTime(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.Format("2006-01-02 15:04:05")
}

// ==================== 三端入口 ====================

func AdminLicenseFileList(c *gin.Context) {
	licenseFileList(c, licenseSiteActor{Type: "admin", ID: contextUserID(c)})
}
func UserLicenseFileList(c *gin.Context) {
	licenseFileList(c, licenseSiteActor{Type: "user", ID: contextUserID(c)})
}
func AgentLicenseFileList(c *gin.Context) {
	licenseFileList(c, licenseSiteActor{Type: "agent", ID: contextUserID(c)})
}
func AdminLicenseFileIssue(c *gin.Context) {
	licenseFileIssue(c, licenseSiteActor{Type: "admin", ID: contextUserID(c)})
}
func UserLicenseFileIssue(c *gin.Context) {
	licenseFileIssue(c, licenseSiteActor{Type: "user", ID: contextUserID(c)})
}
func AgentLicenseFileIssue(c *gin.Context) {
	licenseFileIssue(c, licenseSiteActor{Type: "agent", ID: contextUserID(c)})
}

func AdminLicenseFileDownload(c *gin.Context) {
	licenseFileDownload(c, licenseSiteActor{Type: "admin", ID: contextUserID(c)})
}
func UserLicenseFileDownload(c *gin.Context) {
	licenseFileDownload(c, licenseSiteActor{Type: "user", ID: contextUserID(c)})
}
func AgentLicenseFileDownload(c *gin.Context) {
	licenseFileDownload(c, licenseSiteActor{Type: "agent", ID: contextUserID(c)})
}

func AdminLicenseFileRevoke(c *gin.Context) {
	licenseFileRevoke(c, licenseSiteActor{Type: "admin", ID: contextUserID(c)})
}
func UserLicenseFileRevoke(c *gin.Context) {
	licenseFileRevoke(c, licenseSiteActor{Type: "user", ID: contextUserID(c)})
}
func AgentLicenseFileRevoke(c *gin.Context) {
	licenseFileRevoke(c, licenseSiteActor{Type: "agent", ID: contextUserID(c)})
}
