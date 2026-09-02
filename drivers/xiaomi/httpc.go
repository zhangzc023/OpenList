package xiaomi

// 带自动 Cookie 管理与手工重定向跟随的 HTTP 客户端。
// 必须手工跟随重定向：登录链路每一跳都可能下发关键 Cookie（如 serviceToken）。
// （移植自 mi-drive 的 pkg/httpc，扫码登录链路已实测通过）

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultUA 默认浏览器 UA（小米接口对非浏览器 UA 会降级）
const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

var redirectStatus = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// Options 单次请求选项
type Options struct {
	Method  string
	Headers map[string]string
	Body    io.Reader
	Ctx     context.Context
}

// httpClient HTTP 客户端
type httpClient struct {
	Jar     *Jar
	UA      string
	Timeout time.Duration
	hc      *http.Client
}

// NewHTTPClient 创建客户端
func NewHTTPClient(jar *Jar) *httpClient {
	if jar == nil {
		jar = NewJar()
	}
	return &httpClient{
		Jar:     jar,
		UA:      DefaultUA,
		Timeout: 60 * time.Second,
		hc: &http.Client{
			Timeout: 60 * time.Second,
			// 禁用自动重定向，改由 Request 手工跟随以逐跳收集 Cookie
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ResetJar 重置 Cookie 容器
func (c *httpClient) ResetJar() {
	c.Jar.Reset()
}

// Fetch 发起单次请求（不跟随重定向），自动附加与收集 Cookie
func (c *httpClient) Fetch(rawURL string, opts Options) (*http.Response, error) {
	method := strings.ToUpper(opts.Method)
	if method == "" {
		method = http.MethodGet
	}
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, opts.Body)
	if err != nil {
		return nil, err
	}

	ua := c.UA
	if ua == "" {
		ua = DefaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	if cookieHeader := c.Jar.HeaderFor(rawURL); cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	// 无论状态码如何都要先收集 Set-Cookie
	c.Jar.StoreFromResponse(rawURL, res)
	return res, nil
}

// Request 跟随重定向链的请求（默认最多 10 跳），沿途收集 Cookie
func (c *httpClient) Request(rawURL string, opts Options, maxRedirects int) (*http.Response, error) {
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	method := strings.ToUpper(opts.Method)
	if method == "" {
		method = http.MethodGet
	}
	current := rawURL
	var body io.Reader = opts.Body

	for i := 0; i <= maxRedirects; i++ {
		step := Options{Method: method, Headers: opts.Headers, Ctx: opts.Ctx}
		// 只有第一跳携带 body；GET/HEAD 重定向后不带 body
		if i == 0 || (method != http.MethodGet && method != http.MethodHead) {
			if i == 0 {
				step.Body = body
			}
		}

		res, err := c.Fetch(current, step)
		if err != nil {
			return nil, err
		}

		loc := res.Header.Get("Location")
		if redirectStatus[res.StatusCode] && loc != "" {
			// 丢弃本跳 body，避免连接泄漏
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()

			next, err := resolveURL(current, loc)
			if err != nil {
				return nil, err
			}
			current = next
			// 303，或 301/302 且原方法非 GET/HEAD → 改走 GET
			if res.StatusCode == 303 ||
				((res.StatusCode == 301 || res.StatusCode == 302) && method != http.MethodGet && method != http.MethodHead) {
				method = http.MethodGet
			}
			continue
		}
		return res, nil
	}
	return nil, &RedirectError{URL: rawURL}
}

// RedirectError 重定向次数过多
type RedirectError struct{ URL string }

func (e *RedirectError) Error() string { return "重定向次数过多: " + e.URL }

func resolveURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

// Drain 安全丢弃并关闭响应体
func Drain(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}
