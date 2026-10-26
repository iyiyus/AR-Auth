//go:build unix

package handler

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// 逐级以目录描述符打开，禁止软链；即使上传目录正在替换，也不会越过已打开的根目录。
func openFrontendDiskFile(root, name string) (file *os.File, err error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	parents := []*os.File{os.NewFile(uintptr(fd), root)}
	defer func() {
		for _, parent := range parents {
			err = errors.Join(err, parent.Close())
		}
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err = unix.Openat(fd, part, flags, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return nil, errors.Join(fs.ErrPermission, err)
			}
			return nil, err
		}
		opened := os.NewFile(uintptr(fd), part)
		if i == len(parts)-1 {
			return opened, nil
		}
		parents = append(parents, opened)
	}
	return nil, fs.ErrPermission
}
