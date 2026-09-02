package xiaomi

// 极简但符合浏览器语义的 Cookie 容器。
// 由于容器内的 Cookie 需要跨请求复用并持久化，这里手工维护域名/路径匹配与过期。
// （移植自 mi-drive 的 pkg/cookie，扫码登录链路已实测通过）

import (
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NeverExpire 表示会话级 Cookie（永不过期）
const NeverExpire = int64(math.MaxInt64)

// Cookie 单条 Cookie
type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Expires int64  `json:"expires"` // Unix 毫秒时间戳；NeverExpire 表示不过期
}

// Jar Cookie 容器（并发安全）
type Jar struct {
	mu      sync.RWMutex
	cookies []Cookie
}

func NewJar() *Jar { return &Jar{} }

func normalizeDomain(d string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// domainMatch 判断 host 是否落在 cookie 域名作用域内
func domainMatch(cookieDomain, host string) bool {
	d := normalizeDomain(cookieDomain)
	h := strings.ToLower(host)
	if d == "" {
		return false
	}
	return h == d || strings.HasSuffix(h, "."+d)
}

func pathMatch(cookiePath, reqPath string) bool {
	p := cookiePath
	if p == "" {
		p = "/"
	}
	if p == "/" {
		return true
	}
	base := p
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return reqPath == p || strings.HasPrefix(reqPath, base)
}

// parseCookieDate 兼容带连字符的旧式日期（如 Thu, 01-Dec-1994 16:00:00 GMT）
func parseCookieDate(val string) (int64, bool) {
	s := strings.TrimSpace(val)
	if s == "" {
		return 0, false
	}
	layouts := []string{
		time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC,
	}
	// 旧式连字符日期：先把 01-Dec-1994 变成 01 Dec 1994
	relaxed := strings.NewReplacer("-", " ").Replace(s)
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli(), true
		}
		if t, err := time.Parse(layout, relaxed); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

// specificity 计算具体度：域名越长、路径越长越优先（浏览器语义）
func specificity(c Cookie) int {
	return len(normalizeDomain(c.Domain))*10000 + len(c.pathOrDefault())
}

func (c Cookie) pathOrDefault() string {
	if c.Path == "" {
		return "/"
	}
	return c.Path
}

// StoreFromResponse 从 HTTP 响应的 Set-Cookie 头收集 Cookie
func (j *Jar) StoreFromResponse(reqURL string, res *http.Response) {
	if res == nil {
		return
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return
	}
	rawList := res.Header.Values("Set-Cookie")
	for _, raw := range rawList {
		j.SetFromString(u.Hostname(), raw)
	}
}

// SetFromString 解析一条 Set-Cookie 字符串并存入容器
func (j *Jar) SetFromString(host, raw string) {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return
	}
	eq := strings.Index(parts[0], "=")
	if eq <= 0 {
		return
	}
	name := strings.TrimSpace(parts[0][:eq])
	value := strings.TrimSpace(parts[0][eq+1:])
	if name == "" {
		return
	}

	c := Cookie{Name: name, Value: value, Domain: host, Path: "/", Expires: NeverExpire}
	for _, seg := range parts[1:] {
		idx := strings.Index(seg, "=")
		key := strings.ToLower(strings.TrimSpace(seg))
		val := ""
		if idx >= 0 {
			key = strings.ToLower(strings.TrimSpace(seg[:idx]))
			val = strings.TrimSpace(seg[idx+1:])
		}
		switch key {
		case "domain":
			if val != "" {
				c.Domain = strings.ToLower(val)
			}
		case "path":
			if val != "" {
				c.Path = val
			}
		case "expires":
			if t, ok := parseCookieDate(val); ok {
				c.Expires = t
			}
		case "max-age":
			if s, err := strconv.Atoi(val); err == nil {
				if s <= 0 {
					c.Expires = time.Now().UnixMilli() - 1 // 立即过期 = 删除
				} else {
					c.Expires = time.Now().Add(time.Duration(s) * time.Second).UnixMilli()
				}
			}
		}
	}
	j.set(c)
}

// Set 直接写入一条 Cookie（不指定 domain 时按 host-only 处理）
func (j *Jar) Set(name, value, domain string) {
	j.set(Cookie{Name: name, Value: value, Domain: domain, Path: "/", Expires: NeverExpire})
}

func (j *Jar) set(c Cookie) {
	now := time.Now().UnixMilli()
	domain := normalizeDomain(c.Domain)
	c.Path = c.pathOrDefault()

	j.mu.Lock()
	defer j.mu.Unlock()

	// 同名 + 同域 + 同路径 → 覆盖
	filtered := j.cookies[:0]
	for _, old := range j.cookies {
		same := old.Name == c.Name &&
			normalizeDomain(old.Domain) == domain &&
			old.pathOrDefault() == c.Path
		if same {
			continue
		}
		// 顺带清理已过期项
		if old.Expires <= now {
			continue
		}
		filtered = append(filtered, old)
	}
	j.cookies = filtered

	if c.Expires > now && c.Value != "EXPIRED" && c.Value != "" {
		j.cookies = append(j.cookies, c)
	}
}

func (c Cookie) matches(u *url.URL, now int64) bool {
	if c.Expires <= now {
		return false
	}
	if c.Domain != "" && !domainMatch(c.Domain, u.Hostname()) {
		return false
	}
	return pathMatch(c.Path, u.Path)
}

// HeaderFor 生成请求用的 Cookie 头（同名取最具体的一条）
func (j *Jar) HeaderFor(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	now := time.Now().UnixMilli()

	j.mu.RLock()
	defer j.mu.RUnlock()

	best := make(map[string]Cookie)
	for _, c := range j.cookies {
		if !c.matches(u, now) {
			continue
		}
		if prev, ok := best[c.Name]; !ok || specificity(c) >= specificity(prev) {
			best[c.Name] = c
		}
	}
	if len(best) == 0 {
		return ""
	}
	var sb strings.Builder
	first := true
	for _, c := range best {
		if !first {
			sb.WriteString("; ")
		}
		first = false
		sb.WriteString(c.Name)
		sb.WriteString("=")
		sb.WriteString(c.Value)
	}
	return sb.String()
}

// Get 按名字取最具体域名下的有效 Cookie 值
func (j *Jar) Get(name string) string {
	now := time.Now().UnixMilli()
	j.mu.RLock()
	defer j.mu.RUnlock()

	var best *Cookie
	for i := range j.cookies {
		c := &j.cookies[i]
		if c.Name != name || c.Expires <= now {
			continue
		}
		if best == nil || specificity(*c) >= specificity(*best) {
			best = c
		}
	}
	if best == nil {
		return ""
	}
	return best.Value
}

// Serialize 导出未过期的 Cookie 快照（用于持久化）
func (j *Jar) Serialize() []Cookie {
	now := time.Now().UnixMilli()
	j.mu.RLock()
	defer j.mu.RUnlock()

	out := make([]Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		if c.Expires > now {
			out = append(out, c)
		}
	}
	return out
}

// Deserialize 从快照恢复 Cookie 容器
func Deserialize(arr []Cookie) *Jar {
	j := NewJar()
	if len(arr) > 0 {
		j.cookies = append(j.cookies, arr...)
	}
	return j
}

// Reset 清空容器（重新扫码前调用）
func (j *Jar) Reset() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = nil
}
