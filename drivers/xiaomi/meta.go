package xiaomi

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

// Addition 小米云盘驱动配置。
// 支持三种登录方式（优先级：已保存会话 > Cookie > 扫码）：
//   - 扫码：留空 Cookie，保存后在管理页扫码完成登录（推荐）
//   - Cookie：在 i.mi.com 登录后复制整串 Cookie 粘贴到 cookie 字段
//   - 已保存会话：首次登录后自动写入 session_cookies，之后自动恢复
type Addition struct {
	Cookie         string `json:"cookie" secret:"true" help:"i.mi.com 浏览器 Cookie（留空则使用扫码登录）"`
	ServiceToken   string `json:"service_token" secret:"true" help:"登录凭证（自动维护，无需手动填写）"`
	UserID         string `json:"user_id" help:"小米账号 userId（自动维护）"`
	DeviceID       string `json:"device_id" help:"设备 ID（自动维护）"`
	SessionCookies string `json:"session_cookies" secret:"true" help:"登录会话 Cookie（自动维护）"`
}

var config = driver.Config{
	Name:        "Xiaomi",
	DefaultRoot: "/",
	CheckStatus: true,
	NeedMs:      true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &XiaomiDrive{}
	})
}
