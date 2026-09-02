package xiaomi

import (
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
	"path"
	"strings"
)

// readBody 读取并关闭响应体（限制大小，避免异常响应打爆内存）
func readBody(res *http.Response) ([]byte, error) {
	if res == nil || res.Body == nil {
		return nil, io.EOF
	}
	defer res.Body.Close()
	return io.ReadAll(io.LimitReader(res.Body, 32<<20))
}

// randomDeviceID 生成小米设备 ID（与 Node 版一致的 15 位数字串）
func randomDeviceID() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return strings.Repeat("1", 15)
	}
	s := n.String()
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}

// NormalizePath 规范化虚拟路径：空/根 → "/"，去除末尾斜杠
func NormalizePath(p string) string {
	if p == "" {
		return "/"
	}
	p = path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	return p
}

// ParentPath 返回父目录路径（根目录返回 "/"）
func ParentPath(p string) string {
	p = NormalizePath(p)
	if p == "/" {
		return "/"
	}
	parent := path.Dir(p)
	if parent == "." {
		return "/"
	}
	return parent
}

// BaseName 返回路径最后一段名称
func BaseName(p string) string {
	p = NormalizePath(p)
	if p == "/" {
		return ""
	}
	return path.Base(p)
}

// JoinPath 拼接虚拟路径
func JoinPath(base, name string) string {
	return NormalizePath(path.Join(base, name))
}
