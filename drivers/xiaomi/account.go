package xiaomi

// 小米账号登录状态机（扫码登录 + Cookie 登录）
//
// 扫码登录流程（逆向自 account.xiaomi.com/fe/service/login/qrcode）：
//   a) GET account.xiaomi.com/longPolling/loginUrl?sid=i.mi.com&callback=<URL>
//      callback=https://i.mi.com/sts?sign=<sign>&followup=/
//      sign = base64(sha1("followup=/"))，返回 JSONP {qr, lp, loginUrl, timeout, qrTips}
//   b) GET lp（HTTP 长轮询，阻塞至状态变化或超时）
//   c) 扫码确认返回 {code:0, location} → 跟随重定向链（直达 i.mi.com/sts 兑换 serviceToken）
// （移植自 mi-drive 的 drivers/xiaomi/account.go，扫码登录链路已实测通过）

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// 小米账号服务地址常量
const (
	accountHost = "https://account.xiaomi.com"
	imiHost     = "https://i.mi.com"
	// driveRoot 云盘根目录探测地址（v2 接口，用于校验会话是否有效）
	driveRoot = imiHost + "/drive/v2/user/folders/children?parentId=0&pageNo=1&limit=1&type=&order=SERVICE_TIME&reverse=true"
	// autoRenewal 保活接口
	autoRenewal = imiHost + "/status/setting?type=AutoRenewal&inactiveTime=10&_dc="
	// qrLoginURL 扫码登录二维码创建接口
	qrLoginURL = accountHost + "/longPolling/loginUrl"
	// qrReferer 扫码相关请求的 Referer
	qrReferer = accountHost + "/fe/service/login/qrcode"
	// qrPollTimeout 单次长轮询最长时间（与原项目一致，等待扫码确认时阻塞）
	qrPollTimeout = 60 * time.Second
	// renewalInterval 会话保活间隔
	renewalInterval = 30 * time.Second
)

// MiLoginError 小米登录错误
type MiLoginError struct {
	Code int
	Msg  string
}

func (e *MiLoginError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("登录失败（code=%d）", e.Code)
	}
	return e.Msg
}

// parseJsonpBody 去掉 &&&START&&& 前缀后解析 JSON（小米账号接口的统一返回格式）
func parseJsonpBody(text string) (map[string]any, error) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "&&&START&&&")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseAnyJson 解析 callback({...}) / {...} / &&&START&&&{...} 三种返回格式
func parseAnyJson(text string) (map[string]any, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, nil
	}
	if m, err := parseJsonpBody(s); err == nil && m != nil {
		return m, nil
	}
	// callback({...});
	if i := strings.Index(s, "("); i >= 0 && strings.HasSuffix(s, ")") {
		inner := s[i+1 : len(s)-1]
		inner = strings.TrimSuffix(strings.TrimSpace(inner), ";")
		var m map[string]any
		if err := json.Unmarshal([]byte(inner), &m); err == nil {
			return m, nil
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// jsonNum 兼容小米接口 code 字段可能是数字（float64）或字符串（如 "0"）两种情况
func jsonNum(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case string:
		if f, err := strconv.ParseFloat(n, 64); err == nil {
			return f
		}
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f
		}
	}
	return 0
}

// qrInfo 二维码信息（驱动层保存以支持"保存后再次轮询"）
type qrInfo struct {
	Qr        string
	QrDataUri string
	Lp        string
	LoginUrl  string
	Timeout   int
	QrTips    string
}

// qrStatus 扫码状态
type qrStatus struct {
	Status   string // confirmed | waiting | expired | error
	Location string
	Code     int
	Desc     string
	Error    string
}

// Account 小米账号登录状态机
type Account struct {
	client *httpClient

	mu           sync.Mutex
	state        string // idle | ready
	UserID       string
	ServiceToken string
	DeviceID     string

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// onRenewed serviceToken 自动续期成功后的回调（驱动用它持久化新会话）
	onRenewed func()
}

// NewAccount 创建账号实例
func NewAccount(client *httpClient) *Account {
	return &Account{
		client: client,
		state:  "idle",
		stopCh: make(chan struct{}),
	}
}

// Client 暴露底层 HTTP 客户端（供 api.go 使用）
func (a *Account) Client() *httpClient { return a.client }

// GetServiceToken 安全读取 serviceToken（云盘 API 的鉴权参数）
func (a *Account) GetServiceToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ServiceToken
}

// SetOnRenewed 设置 serviceToken 自动续期成功回调（驱动用它持久化新会话）
func (a *Account) SetOnRenewed(f func()) { a.onRenewed = f }

// TryRenewServiceToken 用 passport 长期会话自动续期 serviceToken。
//
// 机制：请求 i.mi.com 触发服务登录（SSO），服务端发现 serviceToken 失效后
// 302 到 account.xiaomi.com；该域有 passport 长期凭证（passInfo/cUserId/
// deviceId），服务端据此自动登录并 302 回 i.mi.com 重新签发 serviceToken。
// 网页端正是靠这一机制长期免登录（实测：删除 i.mi.com serviceToken 后仅靠
// passport 会话访问 i.mi.com 即自动重签）。
//
// 返回 true 表示续期成功（Jar 与 a.ServiceToken 已更新，且已触发 onRenewed 持久化）。
func (a *Account) TryRenewServiceToken(ctx context.Context) bool {
	hasPassInfo := a.client.Jar.Get("passInfo") != ""
	hasCUserID := a.client.Jar.Get("cUserId") != ""
	log.Infof("[xiaomi] 尝试自动续期 serviceToken（passInfo=%v cUserId=%v deviceId=%v）",
		hasPassInfo, hasCUserID, a.client.Jar.Get("deviceId") != "")
	// 无 passport 长期凭证则无法续期（只能重新扫码）
	if !hasPassInfo && !hasCUserID {
		log.Warn("[xiaomi] 无 passport 长期凭证，无法自动续期，需重新扫码")
		return false
	}
	renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// 重放 SSO：跟随 i.mi.com 首页重定向链，沿途重签 serviceToken
	res, err := a.client.Request(imiHost+"/", Options{Ctx: renewCtx}, 10)
	if err != nil {
		log.Warnf("[xiaomi] 自动续期请求失败: %v", err)
		return false
	}
	Drain(res)
	newST := a.client.Jar.Get("serviceToken")
	if newST == "" {
		log.Warn("[xiaomi] 自动续期后仍未取得 serviceToken")
		return false
	}
	a.mu.Lock()
	a.ServiceToken = newST
	a.mu.Unlock()
	log.Infof("[xiaomi] serviceToken 自动续期成功")
	if a.onRenewed != nil {
		a.onRenewed()
	}
	return true
}

// Ready 是否已登录
func (a *Account) Ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == "ready"
}

// Stop 停止保活定时器
func (a *Account) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopCh)
	})
	a.wg.Wait()
}

// Reset 重置登录态（重新扫码前调用）
func (a *Account) Reset() {
	a.client.ResetJar()
	a.mu.Lock()
	a.state = "idle"
	a.UserID = ""
	a.ServiceToken = ""
	a.DeviceID = ""
	a.mu.Unlock()
}

// SerializeCookies 导出当前 Cookie 快照（供驱动持久化到 Addition）
func (a *Account) SerializeCookies() []Cookie {
	return a.client.Jar.Serialize()
}

// RestoreCookies 从快照恢复 Cookie 容器
func (a *Account) RestoreCookies(cookies []Cookie) {
	a.client.Jar = Deserialize(cookies)
}

// CheckDrive 探测云盘根目录：ok=true 表示会话可用；verifyURL 非空表示需要服务登录
func (a *Account) CheckDrive(ctx context.Context) (ok bool, verifyURL string) {
	res, err := a.client.Fetch(driveRoot, Options{
		Ctx: ctx,
		Headers: map[string]string{
			"accept":  "application/json",
			"referer": imiHost + "/drive/",
		},
	})
	if err != nil {
		return false, ""
	}
	body, err := readBody(res)
	if err != nil {
		return false, ""
	}
	if res.StatusCode == http.StatusOK {
		return true, ""
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err == nil {
		if r, ok := parsed["R"].(float64); ok && r == 401 {
			if d, ok := parsed["D"].(string); ok && d != "" {
				return false, d
			}
		}
	}
	return false, ""
}

// FinishLogin 登录收尾：读取凭证、置为就绪、启动保活。
// 由驱动在扫码/Cookie/恢复会话成功校验后调用。
func (a *Account) FinishLogin() error {
	a.mu.Lock()
	a.ServiceToken = a.client.Jar.Get("serviceToken")
	a.UserID = a.client.Jar.Get("userId")
	a.DeviceID = a.client.Jar.Get("deviceId")
	if a.DeviceID == "" {
		a.DeviceID = randomDeviceID()
		a.client.Jar.Set("deviceId", a.DeviceID, "mi.com")
	}
	if a.ServiceToken == "" {
		a.mu.Unlock()
		return &MiLoginError{Code: -1, Msg: "登录成功但未取得 serviceToken"}
	}
	a.state = "ready"
	a.mu.Unlock()

	a.startRenewal()
	log.Infof("小米账号登录成功（userId=%s）", a.UserID)
	return nil
}

// startRenewal 启动 30s 保活，防止 serviceToken 因不活跃被回收
func (a *Account) startRenewal() {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				if !a.Ready() {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				res, err := a.client.Fetch(autoRenewal+fmt.Sprintf("%d", time.Now().UnixMilli()), Options{
					Ctx: ctx,
					Headers: map[string]string{
						"accept":  "application/json",
						"referer": imiHost + "/drive/",
					},
				})
				if err == nil {
					if res.StatusCode == http.StatusUnauthorized {
						// serviceToken 已失效：尝试用 passport 会话自动续期
						if !a.TryRenewServiceToken(ctx) {
							a.mu.Lock()
							a.state = "idle"
							a.mu.Unlock()
							log.Warn("保活续期失败，会话可能已过期，需重新扫码")
						}
					}
					Drain(res)
				}
				cancel()
			}
		}
	}()
}

// ---------- 扫码登录 ----------

// CreateQRCode 创建扫码登录二维码。
// 返回 qrDataUri（二维码 PNG 的 dataURI）供前端 <img> 直接内联，避免跨域加载失败。
func (a *Account) CreateQRCode(ctx context.Context) (*qrInfo, error) {
	// 每次创建新二维码都重置会话，避免上一轮残留 cookie 干扰
	a.client.ResetJar()
	a.mu.Lock()
	a.state = "idle"
	a.mu.Unlock()

	// 云盘 SSO 的正确 callback：https://i.mi.com/sts?sign=<base64(sha1("followup=/"))>&followup=/
	// 之前误用 account.xiaomi.com?sign=...&followup=（sid=passport），导致扫码确认后
	// passport 无法回跳到 i.mi.com/sts 兑换 serviceToken，被引导到 /pass/auth/security/home，
	// finish 恒失败（"云盘校验未通过"）。实测修正后 location 直达 i.mi.com/sts 并签发 serviceToken。
	followup := "/"
	sum := sha1.Sum([]byte("followup=" + followup))
	sign := base64.StdEncoding.EncodeToString(sum[:])

	// 注意：sign/followup 不再预先 url.QueryEscape —— 由下方 query.Encode() 统一编码一次，
	// 避免 '=' padding 与 '/' 被双重编码为 %253D / %252F。
	callback := fmt.Sprintf("%s/sts?sign=%s&followup=%s", imiHost, sign, followup)
	query := url.Values{}
	query.Set("sid", "i.mi.com")
	query.Set("callback", callback)
	target := qrLoginURL + "?" + query.Encode()

	res, err := a.client.Fetch(target, Options{
		Ctx:     ctx,
		Headers: map[string]string{"referer": qrReferer},
	})
	if err != nil {
		return nil, &MiLoginError{Code: -1, Msg: "创建二维码失败: " + err.Error()}
	}
	body, err := readBody(res)
	if err != nil {
		return nil, &MiLoginError{Code: -1, Msg: "读取二维码响应失败: " + err.Error()}
	}
	parsed, err := parseJsonpBody(string(body))
	if err != nil || parsed == nil {
		return nil, &MiLoginError{Code: res.StatusCode, Msg: "创建二维码响应解析失败"}
	}
	if code, _ := parsed["code"].(float64); code != 0 {
		desc, _ := parsed["desc"].(string)
		if desc == "" {
			desc, _ = parsed["description"].(string)
		}
		if desc == "" {
			desc = "创建二维码失败"
		}
		return nil, &MiLoginError{Code: int(code), Msg: desc}
	}

	qrURL, _ := parsed["qr"].(string)
	lp, _ := parsed["lp"].(string)
	loginURL, _ := parsed["loginUrl"].(string)
	timeout := 300
	if t, ok := parsed["timeout"].(float64); ok && t > 0 {
		timeout = int(t)
	}
	qrTips, _ := parsed["qrTips"].(string)
	if qrTips == "" {
		qrTips = "请使用小米手机或平板扫码登录"
	}

	// 下载二维码 PNG（content-type: image/png），转 base64 dataURI
	dataURI := ""
	if qrURL != "" {
		if imgRes, err := a.client.Fetch(qrURL, Options{
			Ctx:     ctx,
			Headers: map[string]string{"referer": qrReferer},
		}); err == nil {
			if imgRes.StatusCode == http.StatusOK {
				if imgBody, err := readBody(imgRes); err == nil {
					dataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(imgBody)
				}
			} else {
				Drain(imgRes)
			}
		}
	}

	return &qrInfo{
		Qr:        qrURL,
		QrDataUri: dataURI,
		Lp:        lp,
		LoginUrl:  loginURL,
		Timeout:   timeout,
		QrTips:    qrTips,
	}, nil
}

// PollQRStatus 轮询扫码状态（短超时，OpenList 保存操作会被阻塞，故不能长时间挂起）
func (a *Account) PollQRStatus(ctx context.Context, lp string) *qrStatus {
	if lp == "" {
		return &qrStatus{Status: "error", Error: "lp 不能为空"}
	}
	pollCtx, cancel := context.WithTimeout(ctx, qrPollTimeout)
	defer cancel()

	res, err := a.client.Fetch(lp, Options{
		Ctx: pollCtx,
		Headers: map[string]string{
			"referer":    qrReferer,
			"connection": "keep-alive",
		},
	})
	if err != nil {
		// 超时即"等待中"，前端继续保存重试
		if pollCtx.Err() != nil {
			return &qrStatus{Status: "waiting"}
		}
		return &qrStatus{Status: "error", Error: err.Error()}
	}
	body, err := readBody(res)
	if err != nil {
		return &qrStatus{Status: "error", Error: "读取轮询响应失败"}
	}
	// 兼容多种返回格式：&&&START&&&{...} / callback({...}) / {...}
	parsed, err := parseAnyJson(string(body))
	if err != nil || parsed == nil {
		return &qrStatus{Status: "error", Error: "响应无法解析"}
	}
	// 小米 lp 可能返回 code 为数字或字符串（如 "0"），统一处理避免误判 expired
	code := jsonNum(parsed["code"])
	location, _ := parsed["location"].(string)

	if code == 0 && location != "" {
		return &qrStatus{Status: "confirmed", Location: location}
	}
	desc, _ := parsed["desc"].(string)
	if desc == "" {
		desc, _ = parsed["description"].(string)
	}
	if desc == "" {
		desc = "二维码已失效"
	}
	return &qrStatus{Status: "expired", Code: int(code), Desc: desc}
}

// FinishQrLogin 用 lp 返回的 location 完成登录
// 关键点：扫码拿到的是 passport 域（xiaomi.com）的 serviceToken，
// 而 i.mi.com 需要自己的 serviceToken，需访问 i.mi.com 触发 SSO 自动签发。
func (a *Account) FinishQrLogin(ctx context.Context, location string) error {
	if location == "" {
		return &MiLoginError{Code: -1, Msg: "location 不能为空"}
	}

	// 跟随重定向链，沿途收集 passport 会话 Cookie
	res, err := a.client.Request(location, Options{Ctx: ctx}, 10)
	if err != nil {
		return &MiLoginError{Code: -1, Msg: "跟随扫码重定向链失败: " + err.Error()}
	}
	Drain(res)

	// 触发 i.mi.com 服务登录（SSO）
	if res, err := a.client.Request(imiHost+"/", Options{Ctx: ctx}, 10); err == nil {
		Drain(res)
	}

	ok, verify := a.CheckDrive(ctx)
	if ok {
		return a.FinishLogin()
	}

	// verifyUrl 通常是服务登录 URL；若账号风控较重，会指向 /fe/service/identity/authStart
	// 的 SPA 页（手机号在加密 context 中，服务端无法自动完成），只能引导用户去网页端处理。
	if verify != "" {
		log.Warnf("扫码登录后云盘校验返回 verifyUrl（可能为风控验证页）：%s", verify)
		if res, err := a.client.Request(verify, Options{Ctx: ctx}, 10); err == nil {
			Drain(res)
		}
		if ok2, _ := a.CheckDrive(ctx); ok2 {
			return a.FinishLogin()
		}
		return &MiLoginError{Code: 401, Msg: "扫码登录后云盘校验未通过，可能触发了小米安全验证。请尝试：1) 刷新二维码重新扫码；2) 先到 i.mi.com 网页端登录，再回来重试"}
	}
	return &MiLoginError{Code: 401, Msg: "扫码登录后云盘校验未通过，请刷新二维码重试（若多次失败，建议先到 i.mi.com 网页端登录）"}
}

// LoginWithCookie 手动 Cookie 登录（浏览器复制的整串）
func (a *Account) LoginWithCookie(ctx context.Context, cookieString string) error {
	s := strings.TrimSpace(cookieString)
	if s == "" {
		return &MiLoginError{Code: -1, Msg: "Cookie 为空"}
	}
	a.client.ResetJar()
	a.mu.Lock()
	a.state = "idle"
	a.mu.Unlock()

	count := 0
	for _, pair := range strings.Split(s, ";") {
		idx := strings.Index(pair, "=")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])
		if name == "" || value == "" {
			continue
		}
		// 同时挂到 mi.com 与 xiaomi.com 两个域，覆盖 i.mi.com 与账号站
		a.client.Jar.Set(name, value, "mi.com")
		a.client.Jar.Set(name, value, "xiaomi.com")
		count++
	}
	if count == 0 {
		return &MiLoginError{Code: -1, Msg: "Cookie 格式无法解析"}
	}
	if a.client.Jar.Get("serviceToken") == "" {
		// 仅在缺少 serviceToken 时给出提示，仍尝试校验（部分场景可能用其他凭证）
		log.Warn("Cookie 中未发现 serviceToken，登录大概率会失败（请确认复制的是 i.mi.com 的 Cookie）")
	}

	ok, _ := a.CheckDrive(ctx)
	if ok {
		return a.FinishLogin()
	}
	return &MiLoginError{Code: 401, Msg: "Cookie 无效或已过期，请重新从浏览器复制"}
}
