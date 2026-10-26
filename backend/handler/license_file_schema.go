package handler

import (
	"database/sql"
	"strings"
	"sync"
)

var (
	licenseFileSchemaMu sync.Mutex
	licenseFileSchemaOK bool
)

// EnsureLicenseFileSchema 补齐 License 文件授权所需的表结构与字段。
// 对已安装的库做幂等迁移：扩展 licenses.type 枚举、新增 apps 密钥列、创建 license_files 表。
func EnsureLicenseFileSchema(db *sql.DB) error {
	licenseFileSchemaMu.Lock()
	defer licenseFileSchemaMu.Unlock()
	if licenseFileSchemaOK {
		return nil
	}

	if err := ensureLicenseTypeFileOption(db); err != nil {
		return err
	}
	if err := ensureAppsLicenseKeyColumns(db); err != nil {
		return err
	}
	if err := ensureLicenseFilesTable(db); err != nil {
		return err
	}

	licenseFileSchemaOK = true
	return nil
}

func ensureLicenseTypeFileOption(db *sql.DB) error {
	var columnType string
	if err := db.QueryRow(`
		SELECT COLUMN_TYPE
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE()
		  AND TABLE_NAME = 'licenses'
		  AND COLUMN_NAME = 'type'
	`).Scan(&columnType); err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(columnType), "'file'") {
		return nil
	}
	if _, err := db.Exec(`
		ALTER TABLE licenses
		MODIFY COLUMN ` + "`type`" + ` ENUM('domain','wildcard','ip','key','file') NOT NULL COMMENT '授权类型: domain/wildcard/ip/key/file授权文件'
	`); err != nil {
		return err
	}
	return nil
}

func ensureAppsLicenseKeyColumns(db *sql.DB) error {
	columns := []struct {
		name       string
		definition string
	}{
		{"license_public_key", "TEXT COMMENT 'License 文件授权 RSA 公钥(PEM/PKIX)'"},
		{"license_private_key", "TEXT COMMENT 'License 文件授权 RSA 私钥(PEM/PKCS1)'"},
		{"license_key_updated_at", "DATETIME NULL COMMENT 'License 文件 RSA 密钥对生成/轮换时间'"},
	}
	for _, column := range columns {
		var exists int
		if err := db.QueryRow(`
			SELECT COUNT(*)
			FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE()
			  AND TABLE_NAME = 'apps'
			  AND COLUMN_NAME = ?
		`, column.name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		if _, err := db.Exec("ALTER TABLE apps ADD COLUMN " + column.name + " " + column.definition); err != nil {
			return err
		}
	}
	return nil
}

func ensureLicenseFilesTable(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS license_files (
		  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
		  file_no        VARCHAR(32)  NOT NULL COMMENT '授权文件编号(对外标识)',
		  license_id     BIGINT UNSIGNED NOT NULL COMMENT '所属授权ID',
		  app_id         BIGINT UNSIGNED NOT NULL COMMENT '所属应用ID',
		  bind_domains   TEXT COMMENT '绑定域名列表(JSON数组)',
		  bind_ips       TEXT COMMENT '绑定服务器IP列表(JSON数组)',
		  bind_machines  TEXT COMMENT '绑定机器码列表(JSON数组)',
		  heartbeat_days INT NOT NULL DEFAULT 30 COMMENT '心跳周期(天), 0表示不做周期回源',
		  grace_days     INT NOT NULL DEFAULT 7 COMMENT '离线宽限天数',
		  status         ENUM('active','revoked') NOT NULL DEFAULT 'active' COMMENT '状态',
		  revoked_at     DATETIME DEFAULT NULL COMMENT '吊销时间',
		  revoke_reason  VARCHAR(200) NOT NULL DEFAULT '' COMMENT '吊销原因',
		  expire_at      DATETIME DEFAULT NULL COMMENT '文件有效期快照',
		  payload        LONGTEXT NOT NULL COMMENT '授权文件原文',
		  last_seen_at   DATETIME DEFAULT NULL COMMENT '最近一次在线回源时间',
		  last_domain    VARCHAR(255) NOT NULL DEFAULT '' COMMENT '最近上报域名',
		  last_ip        VARCHAR(45)  NOT NULL DEFAULT '' COMMENT '最近上报服务器IP',
		  last_machine   VARCHAR(128) NOT NULL DEFAULT '' COMMENT '最近上报机器码',
		  created_by     VARCHAR(20) NOT NULL DEFAULT 'admin' COMMENT '签发端: admin/user/agent',
		  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '签发时间',
		  updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
		  PRIMARY KEY (id),
		  UNIQUE KEY uk_file_no (file_no),
		  KEY idx_license (license_id),
		  KEY idx_app (app_id),
		  KEY idx_status (status)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='License 文件授权表'
	`); err != nil {
		return err
	}
	return nil
}
