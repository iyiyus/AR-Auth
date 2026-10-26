package handler

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var errFrontendProtectedRoot = errors.New("frontend root belongs to installed package")

// FrontendHandler 为未匹配业务路由的请求提供 PC 或移动端页面。
// H5 只影响页面入口，资源按路径固定来源，避免切换 UA 后混用两个构建。
func FrontendHandler(embedded fs.FS, frontendDir, h5Dir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Gin 的 NoRoute 会补写默认 404 正文，HEAD 必须提前提交空响应。
		if c.Request.Method == http.MethodHead {
			defer c.Writer.WriteHeaderNow()
		}
		requestPath := c.Request.URL.Path
		if frontendReservedPath(requestPath) {
			if c.Request.Method == http.MethodHead {
				c.Status(http.StatusNotFound)
			} else {
				c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "请求的资源不存在"})
			}
			return
		}
		name, ok := frontendPath(requestPath)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Header("Allow", "GET, HEAD")
			c.Status(http.StatusMethodNotAllowed)
			return
		}
		c.Header("X-Content-Type-Options", "nosniff")
		if name == "h5-assets" || strings.HasPrefix(name, "h5-assets/") {
			serveFrontendDisk(c, h5Dir, name, false)
			return
		}

		isPage := name == "" || name == "index.html" || (path.Ext(name) == "" && name != "assets" && !strings.HasPrefix(name, "assets/"))
		if isPage {
			if name != "" && name != "index.html" {
				if _, err := fs.Stat(embedded, name); err == nil {
					c.Status(http.StatusNotFound)
					return
				}
				for _, directory := range []string{frontendDir, h5Dir} {
					file, err := openFrontendFile(directory, name)
					if file != nil {
						closeFrontendFile(file)
					}
					if errors.Is(err, errFrontendProtectedRoot) {
						continue
					}
					if err == nil || errors.Is(err, fs.ErrPermission) {
						c.Status(http.StatusNotFound)
						return
					}
				}
			}
			// 入口不可长期缓存，且必须与 UA 一起参与代理缓存键。
			c.Writer.Header().Add("Vary", "User-Agent")
			c.Header("Cache-Control", "no-cache")
			if name != "install" && !strings.HasPrefix(name, "install/") && frontendMobileUA(c.Request.UserAgent()) {
				if serveFrontendDisk(c, h5Dir, "index.html", true) {
					return
				}
			}
			if serveFrontendDisk(c, frontendDir, "index.html", true) {
				return
			}
			serveFrontendEmbedded(c, embedded, "index.html", true)
			return
		}

		// 与旧版本保持一致：PC 磁盘入口存在时整套 PC 资源来自磁盘。
		index, err := openFrontendFile(frontendDir, "index.html")
		if index != nil {
			closeFrontendFile(index)
		}
		if err == nil {
			serveFrontendDisk(c, frontendDir, name, false)
			return
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			slog.Warn("frontend PC entry unavailable", "error", err)
		}
		serveFrontendEmbedded(c, embedded, name, false)
	}
}

func frontendReservedPath(requestPath string) bool {
	for _, prefix := range []string{"/api", "/realname-face", "/admin/app-store"} {
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}
	return false
}

func frontendPath(requestPath string) (string, bool) {
	if !strings.HasPrefix(requestPath, "/") || strings.Contains(requestPath, "//") || strings.ContainsAny(requestPath, "\\\x00%:") {
		return "", false
	}
	name := strings.TrimPrefix(requestPath, "/")
	for _, segment := range strings.Split(name, "/") {
		lower := strings.ToLower(segment)
		if strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return "", false
		}
		device := strings.SplitN(lower, ".", 2)[0]
		if device == "con" || device == "prn" || device == "aux" || device == "nul" ||
			(len(device) == 4 && (strings.HasPrefix(device, "com") || strings.HasPrefix(device, "lpt")) && device[3] >= '1' && device[3] <= '9') {
			return "", false
		}
		switch lower {
		case "backend", "plugins", "home-templates", "updates", "app-releases", "software-source-cache", "db.json", "jwt.secret", "install.lock", "go.mod", "go.sum", "package.json", "package-lock.json", "pnpm-lock.yaml", "config.json":
			return "", false
		}
	}
	name = strings.TrimSuffix(name, "/")
	if name != "" && !fs.ValidPath(name) {
		return "", false
	}
	if ext := strings.ToLower(path.Ext(name)); ext != "" {
		switch ext {
		case ".html", ".css", ".js", ".mjs", ".json", ".webmanifest", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".txt", ".xml", ".mp4", ".webm", ".mp3", ".ogg", ".wav", ".pdf":
		default:
			return "", false
		}
	}
	return name, true
}

func frontendMobileUA(ua string) bool {
	ua = strings.ToLower(ua)
	for _, marker := range []string{"iphone", "ipad", "ipod", "android", "mobile", "windows phone", "iemobile", "blackberry", "opera mini"} {
		if strings.Contains(ua, marker) {
			return true
		}
	}
	return false
}

func openFrontendFile(directory, name string) (*os.File, error) {
	if directory == "" {
		return nil, fs.ErrNotExist
	}
	if _, ok := frontendPath("/" + name); !ok || name == "" {
		return nil, fs.ErrPermission
	}
	root, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	if IsInstalledPackageFile(root) {
		return nil, errors.Join(fs.ErrPermission, errFrontendProtectedRoot)
	}
	filename := filepath.Join(root, filepath.FromSlash(name))
	if IsInstalledPackageFile(filename) {
		return nil, fs.ErrPermission
	}
	file, err := openFrontendDiskFile(root, name)
	if err != nil {
		if file != nil {
			closeFrontendFile(file)
		}
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		closeFrontendFile(file)
		if err != nil {
			return nil, err
		}
		return nil, fs.ErrPermission
	}
	if name == "index.html" && info.Size() == 0 {
		closeFrontendFile(file)
		return nil, fs.ErrNotExist
	}
	return file, nil
}

func serveFrontendDisk(c *gin.Context, directory, name string, optional bool) bool {
	file, err := openFrontendFile(directory, name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			slog.Warn("frontend static file unavailable", "error", err)
		}
		if optional {
			return false
		}
		c.Status(http.StatusNotFound)
		return true
	}
	defer closeFrontendFile(file)
	info, err := file.Stat()
	if err != nil {
		slog.Error("frontend static file stat failed", "error", err)
		if optional {
			return false
		}
		c.Status(http.StatusInternalServerError)
		return true
	}
	// 页面总是返回完整入口，避免 PC/H5 恰好有相同修改时间时错误返回 304。
	modTime := time.Time{}
	if !optional {
		modTime = info.ModTime()
	}
	http.ServeContent(c.Writer, c.Request, name, modTime, file)
	return true
}

func serveFrontendEmbedded(c *gin.Context, embedded fs.FS, name string, page bool) {
	data, err := fs.ReadFile(embedded, name)
	if err != nil {
		if page {
			slog.Error("embedded frontend entry unavailable", "error", err)
			c.Status(http.StatusInternalServerError)
		} else {
			c.Status(http.StatusNotFound)
		}
		return
	}
	http.ServeContent(c.Writer, c.Request, name, time.Time{}, bytes.NewReader(data))
}

func closeFrontendFile(file *os.File) {
	if err := file.Close(); err != nil {
		slog.Warn("frontend static file close failed", "error", err)
	}
}
