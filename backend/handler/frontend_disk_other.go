//go:build !unix && !windows

package handler

import (
	"io/fs"
	"os"
)

// 未提供安全相对路径打开的平台保留内嵌 PC，避免静态目录逃逸。
func openFrontendDiskFile(root, name string) (*os.File, error) {
	return nil, fs.ErrNotExist
}
