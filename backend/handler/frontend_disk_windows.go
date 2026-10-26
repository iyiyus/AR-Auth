//go:build windows

package handler

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Windows 按已打开句柄的最终路径验证边界，避免检查路径后软链被替换。
func openFrontendDiskFile(root, name string) (file *os.File, err error) {
	directory, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	rootPath, err := frontendWindowsHandlePath(directory)
	if err != nil {
		return nil, err
	}
	if IsInstalledPackageFile(rootPath) {
		return nil, errors.Join(fs.ErrPermission, errFrontendProtectedRoot)
	}
	filename := root
	for _, part := range strings.Split(name, "/") {
		filename = filepath.Join(filename, part)
		info, err := os.Lstat(filename)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fs.ErrPermission
		}
	}
	file, err = os.Open(filename)
	if err != nil {
		return nil, err
	}
	finalPath, err := frontendWindowsHandlePath(file)
	if err != nil {
		return file, err
	}
	prefix := strings.TrimRight(rootPath, "\\") + "\\"
	if !strings.HasPrefix(strings.ToLower(finalPath), strings.ToLower(prefix)) {
		return file, fs.ErrPermission
	}
	relative := filepath.ToSlash(finalPath[len(prefix):])
	if _, ok := frontendPath("/" + relative); !ok || IsInstalledPackageFile(finalPath) {
		return file, fs.ErrPermission
	}
	return file, nil
}

func frontendWindowsHandlePath(file *os.File) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buffer)) {
		return "", fs.ErrPermission
	}
	name := windows.UTF16ToString(buffer[:n])
	if strings.HasPrefix(name, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(name, `\\?\UNC\`), nil
	}
	return strings.TrimPrefix(name, `\\?\`), nil
}
