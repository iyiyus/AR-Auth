package handler

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

const frontendTestMobileUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1"

func frontendTestWrite(t *testing.T, root, name, content string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func frontendTestRouter(embedded fs.FS, pc, h5 string) *gin.Engine {
	r := gin.New()
	r.NoRoute(FrontendHandler(embedded, pc, h5))
	return r
}

func frontendTestRequest(r http.Handler, method, target, ua string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("User-Agent", ua)
	response := httptest.NewRecorder()
	r.ServeHTTP(response, request)
	return response
}

func TestFrontendHandler(t *testing.T) {
	t.Setenv("AUTO_PRO_DATA_DIR", t.TempDir())
	pc, h5 := t.TempDir(), t.TempDir()
	frontendTestWrite(t, pc, "index.html", "PC disk page")
	frontendTestWrite(t, pc, "assets/app.js", "PC resource")
	frontendTestWrite(t, pc, "logo.svg", "PC logo")
	frontendTestWrite(t, pc, "h5-assets/app.js", "wrong PC H5 resource")
	frontendTestWrite(t, h5, "index.html", "H5 page")
	frontendTestWrite(t, h5, "h5-assets/app.js", "H5 resource")
	frontendTestWrite(t, h5, "assets/app.js", "wrong H5 PC resource")
	frontendTestWrite(t, h5, "logo.svg", "wrong H5 logo")
	embedded := fstest.MapFS{
		"index.html":    {Data: []byte("PC embedded page")},
		"assets/app.js": {Data: []byte("PC embedded resource")},
	}
	r := frontendTestRouter(embedded, pc, h5)
	cases := []struct {
		name, method, target, ua string
		status                   int
		body                     string
		page                     bool
	}{
		{"desktop root", "GET", "/", "Mozilla/5.0 Windows NT", 200, "PC disk page", true},
		{"mobile root", "GET", "/", frontendTestMobileUA, 200, "H5 page", true},
		{"mobile user", "GET", "/user/licenses?tab=all", frontendTestMobileUA, 200, "H5 page", true},
		{"mobile agent", "GET", "/agent-panel/purchase", frontendTestMobileUA, 200, "H5 page", true},
		{"mobile admin login", "GET", "/admin", frontendTestMobileUA, 200, "H5 page", true},
		{"mobile admin dashboard", "GET", "/dashboard", frontendTestMobileUA, 200, "H5 page", true},
		{"mobile admin system", "GET", "/system/config", frontendTestMobileUA, 200, "H5 page", true},
		{"direct mobile index", "GET", "/index.html", frontendTestMobileUA, 200, "H5 page", true},
		{"install remains PC", "GET", "/install", frontendTestMobileUA, 200, "PC disk page", true},
		{"install trailing slash", "GET", "/install/", frontendTestMobileUA, 200, "PC disk page", true},
		{"PC resource desktop", "GET", "/assets/app.js", "Desktop", 200, "PC resource", false},
		{"PC resource mobile", "GET", "/assets/app.js", frontendTestMobileUA, 200, "PC resource", false},
		{"PC public file mobile", "GET", "/logo.svg", frontendTestMobileUA, 200, "PC logo", false},
		{"H5 resource desktop", "GET", "/h5-assets/app.js", "Desktop", 200, "H5 resource", false},
		{"H5 resource mobile", "GET", "/h5-assets/app.js", frontendTestMobileUA, 200, "H5 resource", false},
		{"missing H5 resource", "GET", "/h5-assets/missing.js", frontendTestMobileUA, 404, "", false},
		{"missing PC resource", "GET", "/assets/missing.js", frontendTestMobileUA, 404, "", false},
		{"missing extensionless H5 resource", "GET", "/h5-assets/missing", frontendTestMobileUA, 404, "", false},
		{"missing extensionless PC resource", "GET", "/assets/missing", frontendTestMobileUA, 404, "", false},
		{"PC directory", "GET", "/assets", frontendTestMobileUA, 404, "", false},
		{"H5 directory", "GET", "/h5-assets/", frontendTestMobileUA, 404, "", false},
		{"unknown API", "GET", "/api/not-found", frontendTestMobileUA, 404, "", false},
		{"head unknown API", "HEAD", "/api/not-found", frontendTestMobileUA, 404, "", false},
		{"API root", "GET", "/api", frontendTestMobileUA, 404, "", false},
		{"API slash", "GET", "/api/", frontendTestMobileUA, 404, "", false},
		{"head H5 page", "HEAD", "/user/licenses", frontendTestMobileUA, 200, "", true},
		{"head PC page", "HEAD", "/admin", "Desktop", 200, "", true},
		{"head H5 resource", "HEAD", "/h5-assets/app.js", "Desktop", 200, "", false},
		{"head missing H5 resource", "HEAD", "/h5-assets/missing.js", "Desktop", 404, "", false},
		{"head unsafe path", "HEAD", "/db.json", frontendTestMobileUA, 404, "", false},
		{"head PC resource", "HEAD", "/assets/app.js", frontendTestMobileUA, 200, "", false},
		{"post page", "POST", "/user/licenses", frontendTestMobileUA, 405, "", false},
		{"put resource", "PUT", "/h5-assets/app.js", frontendTestMobileUA, 405, "", false},
		{"delete page", "DELETE", "/admin", frontendTestMobileUA, 405, "", false},
		{"options fallback", "OPTIONS", "/", frontendTestMobileUA, 405, "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			response := frontendTestRequest(r, tt.method, tt.target, tt.ua)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, tt.status, response.Body.String())
			}
			if tt.body != "" && response.Body.String() != tt.body {
				t.Fatalf("body = %q, want %q", response.Body.String(), tt.body)
			}
			if tt.method == "HEAD" && response.Body.Len() != 0 {
				t.Fatalf("HEAD returned body: %q", response.Body.String())
			}
			if tt.status == 404 && (strings.Contains(response.Body.String(), "PC disk page") || strings.Contains(response.Body.String(), "H5 page") || strings.Contains(response.Body.String(), "PC embedded page")) {
				t.Fatalf("missing resource incorrectly returned SPA: %q", response.Body.String())
			}
			if tt.page {
				if response.Header().Get("Cache-Control") != "no-cache" || response.Header().Get("Vary") != "User-Agent" {
					t.Fatalf("page cache headers: %v", response.Header())
				}
			} else if response.Header().Get("Vary") != "" {
				t.Fatalf("resource response varies by UA: %v", response.Header())
			}
			if tt.status == 405 && response.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("Allow = %q", response.Header().Get("Allow"))
			}
		})
	}
}

func TestFrontendHandlerDynamicDeployment(t *testing.T) {
	t.Setenv("AUTO_PRO_DATA_DIR", t.TempDir())
	root := t.TempDir()
	pc, h5 := filepath.Join(root, "pc"), filepath.Join(root, "h5")
	embedded := fstest.MapFS{
		"index.html":           {Data: []byte("PC embedded page")},
		"assets/app.js":        {Data: []byte("PC embedded resource")},
		"h5-assets/missing.js": {Data: []byte("wrong embedded H5 resource")},
	}
	r := frontendTestRouter(embedded, pc, h5)
	steps := []struct {
		name  string
		apply func()
		page  string
	}{
		{"no disk deployments", func() {}, "PC embedded page"},
		{"late PC upload", func() { frontendTestWrite(t, pc, "index.html", "PC disk page") }, "PC disk page"},
		{"H5 assets without entry", func() { frontendTestWrite(t, h5, "h5-assets/app.js", "H5 resource") }, "PC disk page"},
		{"empty H5 upload", func() { frontendTestWrite(t, h5, "index.html", "") }, "PC disk page"},
		{"late H5 upload", func() { frontendTestWrite(t, h5, "index.html", "H5 first page") }, "H5 first page"},
		{"H5 replace", func() { frontendTestWrite(t, h5, "index.html", "H5 next page") }, "H5 next page"},
		{"H5 entry remove", func() {
			if err := os.Remove(filepath.Join(h5, "index.html")); err != nil {
				t.Fatal(err)
			}
		}, "PC disk page"},
		{"H5 directory remove", func() {
			if err := os.RemoveAll(h5); err != nil {
				t.Fatal(err)
			}
		}, "PC disk page"},
		{"PC entry remove", func() {
			if err := os.Remove(filepath.Join(pc, "index.html")); err != nil {
				t.Fatal(err)
			}
		}, "PC embedded page"},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.apply()
			response := frontendTestRequest(r, "GET", "/admin", frontendTestMobileUA)
			if response.Code != 200 || response.Body.String() != step.page {
				t.Fatalf("response = %d %q, want 200 %q", response.Code, response.Body.String(), step.page)
			}
			if response.Header().Get("Cache-Control") != "no-cache" || response.Header().Get("Vary") != "User-Agent" {
				t.Fatalf("fallback cache headers: %v", response.Header())
			}
			missing := frontendTestRequest(r, "GET", "/h5-assets/missing.js", "Desktop")
			if missing.Code != 404 {
				t.Fatalf("missing H5 asset status = %d", missing.Code)
			}
		})
	}
	resource := frontendTestRequest(r, "GET", "/assets/app.js", frontendTestMobileUA)
	if resource.Code != 200 || resource.Body.String() != "PC embedded resource" {
		t.Fatalf("embedded PC resource = %d %q", resource.Code, resource.Body.String())
	}
}

func TestFrontendMobileUA(t *testing.T) {
	cases := []struct {
		ua     string
		mobile bool
	}{
		{frontendTestMobileUA, true}, {"iPad", true}, {"iPod", true}, {"Android Tablet", true},
		{"Mobile Safari", true}, {"Windows Phone 10.0", true}, {"IEMobile", true},
		{"BlackBerry", true}, {"Opera Mini", true}, {"ANDROID", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", false},
		{"Macintosh Touch", false}, {"Windows NT 10.0", false}, {"X11 Linux x86_64", false}, {"", false},
	}
	for _, tt := range cases {
		t.Run(tt.ua, func(t *testing.T) {
			if got := frontendMobileUA(tt.ua); got != tt.mobile {
				t.Fatalf("mobile = %v, want %v", got, tt.mobile)
			}
		})
	}
}

func TestFrontendHandlerUnsafePaths(t *testing.T) {
	data, pc, h5 := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("AUTO_PRO_DATA_DIR", data)
	frontendTestWrite(t, pc, "index.html", "PC page")
	frontendTestWrite(t, h5, "index.html", "H5 page")
	paths := []string{
		"/db.json", "/nested/db.json", "/jwt.secret", "/install.lock", "/.env", "/.git/config",
		"/backend/db.json", "/plugins/example/index.html", "/home-templates/example/index.html",
		"/private.pem", "/private.key", "/backup.sql", "/config.yaml", "/source.go", "/assets/app.js.map",
		"/index.html/../db.json", "/h5-assets/../../index.html", "/%2e%2e/index.html",
		"/h5-assets/%2e%2e/db.json", "/%252e%252e/index.html", "/h5-assets/%5c..%5cindex.html",
		"/h5-assets/file.js%00", "/h5-assets/C:%5csecret.js", "/h5-assets//app.js",
		"/h5-assets/file.js.", "/h5-assets/file.js%20", "/package.json", "/config.json",
		"//", "//index.html", "/h5-assets/NUL.js", "/h5-assets/COM1", "/h5-assets/LPT1.txt",
	}
	r := frontendTestRouter(fstest.MapFS{"index.html": {Data: []byte("embedded page")}}, pc, h5)
	for _, target := range paths {
		t.Run(target, func(t *testing.T) {
			for _, ua := range []string{"Desktop", frontendTestMobileUA} {
				response := frontendTestRequest(r, "GET", target, ua)
				if response.Code != 404 {
					t.Fatalf("unsafe path status = %d, body=%q", response.Code, response.Body.String())
				}
			}
		})
	}
	for _, root := range []string{pc, h5} {
		for _, name := range []string{"db.json", ".env", "private.pem"} {
			frontendTestWrite(t, root, name, "sensitive content")
		}
	}
	if response := frontendTestRequest(r, "GET", "/db.json", frontendTestMobileUA); response.Code != 404 {
		t.Fatal("existing sensitive file was served")
	}
}

func TestFrontendHandlerSymlinks(t *testing.T) {
	data, pc, h5, outside := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("AUTO_PRO_DATA_DIR", data)
	frontendTestWrite(t, pc, "index.html", "PC page")
	frontendTestWrite(t, h5, "index.html", "H5 page")
	frontendTestWrite(t, outside, "secret.js", "outside secret")
	frontendTestWrite(t, pc, "db.json", "sensitive JSON")
	frontendTestWrite(t, data, "plugins/example/index.html", "installed plugin")
	frontendTestWrite(t, data, "home-templates/example/index.html", "installed template")
	links := []struct{ target, link string }{
		{filepath.Join(outside, "secret.js"), filepath.Join(pc, "leak.js")},
		{outside, filepath.Join(pc, "leak-dir")},
		{filepath.Join(outside, "secret.js"), filepath.Join(h5, "h5-assets", "leak.js")},
		{outside, filepath.Join(h5, "h5-assets", "leak-dir")},
		{filepath.Join(pc, "db.json"), filepath.Join(pc, "alias.json")},
		{filepath.Join(data, "plugins"), filepath.Join(pc, "alias-plugin")},
		{filepath.Join(data, "home-templates"), filepath.Join(pc, "alias-template")},
	}
	for _, link := range links {
		if err := os.MkdirAll(filepath.Dir(link.link), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(link.target, link.link); err != nil {
			t.Fatal(err)
		}
	}
	r := frontendTestRouter(fstest.MapFS{"index.html": {Data: []byte("embedded page")}}, pc, h5)
	for _, target := range []string{"/leak.js", "/leak-dir/secret.js", "/leak-dir", "/h5-assets/leak.js", "/h5-assets/leak-dir/secret.js", "/alias.json", "/alias-plugin/example/index.html", "/alias-template/example/index.html"} {
		t.Run(target, func(t *testing.T) {
			response := frontendTestRequest(r, "GET", target, frontendTestMobileUA)
			if response.Code != 404 || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("symlink response = %d %q", response.Code, response.Body.String())
			}
		})
	}
	if err := os.Remove(filepath.Join(h5, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(pc, "index.html"), filepath.Join(h5, "index.html")); err != nil {
		t.Fatal(err)
	}
	response := frontendTestRequest(r, "GET", "/admin", frontendTestMobileUA)
	if response.Code != 200 || response.Body.String() != "PC page" {
		t.Fatalf("unsafe H5 entry fallback = %d %q", response.Code, response.Body.String())
	}

	// 根目录允许部署级链接；根目录内仍禁止软链。
	current := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(pc, current); err != nil {
		t.Fatal(err)
	}
	r = frontendTestRouter(fstest.MapFS{}, current, "")
	response = frontendTestRequest(r, "GET", "/admin", "Desktop")
	if response.Code != 200 || response.Body.String() != "PC page" {
		t.Fatalf("deployment root symlink = %d %q", response.Code, response.Body.String())
	}

	r = frontendTestRouter(fstest.MapFS{"index.html": {Data: []byte("embedded page")}}, filepath.Join(data, "plugins", "example"), "")
	response = frontendTestRequest(r, "GET", "/admin", "Desktop")
	if response.Code != 200 || response.Body.String() != "embedded page" {
		t.Fatalf("installed package entry fallback = %d %q", response.Code, response.Body.String())
	}
}

func TestFrontendHandlerRegisteredRoutes(t *testing.T) {
	t.Setenv("AUTO_PRO_DATA_DIR", t.TempDir())
	h5 := t.TempDir()
	frontendTestWrite(t, h5, "index.html", "H5 page")
	r := frontendTestRouter(fstest.MapFS{}, "", h5)
	for _, target := range []string{"/api/status", "/realname-face", "/admin/app-store", "/admin/app-store/apps", "/api/payment/easypay/notify", "/api/payment/easypay/return"} {
		r.Any(target, func(c *gin.Context) { c.String(200, "business route") })
		t.Run(target, func(t *testing.T) {
			response := frontendTestRequest(r, "GET", target, frontendTestMobileUA)
			if response.Code != 200 || response.Body.String() != "business route" {
				t.Fatalf("registered route = %d %q", response.Code, response.Body.String())
			}
		})
	}
	for _, target := range []string{"/realname-face/missing", "/admin/app-store/missing"} {
		if response := frontendTestRequest(r, "GET", target, frontendTestMobileUA); response.Code != 404 {
			t.Fatalf("reserved route %s returned %d", target, response.Code)
		}
	}
}

func TestFrontendHandlerCacheAndMissingEntry(t *testing.T) {
	t.Setenv("AUTO_PRO_DATA_DIR", t.TempDir())
	pc, h5 := t.TempDir(), t.TempDir()
	frontendTestWrite(t, pc, "index.html", "PC page")
	frontendTestWrite(t, h5, "index.html", "H5 page")
	r := frontendTestRouter(fstest.MapFS{}, pc, h5)
	r.Use(func(c *gin.Context) { c.Header("Vary", "Accept-Encoding"); c.Next() })
	request := httptest.NewRequest("GET", "/admin", nil)
	request.Header.Set("User-Agent", frontendTestMobileUA)
	request.Header.Set("If-Modified-Since", "Wed, 01 Jan 2099 00:00:00 GMT")
	response := httptest.NewRecorder()
	r.ServeHTTP(response, request)
	if response.Code != 200 || response.Body.String() != "H5 page" {
		t.Fatalf("conditional UA page = %d %q", response.Code, response.Body.String())
	}
	vary := strings.Join(response.Header().Values("Vary"), ",")
	if !strings.Contains(vary, "Accept-Encoding") || !strings.Contains(vary, "User-Agent") {
		t.Fatalf("Vary = %q", vary)
	}
	r = frontendTestRouter(fstest.MapFS{}, "", "")
	response = frontendTestRequest(r, "GET", "/", "Desktop")
	if response.Code != 500 {
		t.Fatalf("missing all entries = %d", response.Code)
	}
}
