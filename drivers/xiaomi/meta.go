package xiaomi

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

// Addition 小米云盘驱动配置。
// 支持三种登录方式（优先级：已保存会话 > Cookie > 扫码）：
//   - 扫码：留空 Cookie，保存后在管理页扫码完成登录（推荐，自动保存 passport 长期凭证）
//   - Cookie：在 i.mi.com 登录后复制整串 Cookie 粘贴到 cookie 字段；
//     若想支持自动续期，请同时包含 account.xiaomi.com 域的 passInfo/cUserId 等凭证
//   - 已保存会话：首次登录后自动写入 session_cookies，之后自动恢复并可自动续期
//
// 注：service_token / user_id / device_id 为冗余字段（驱动只写不读），已移除。
type Addition struct {
	Cookie         string `json:"cookie" secret:"true" help:"i.mi.com 浏览器 Cookie（留空则使用扫码登录）"`
	SessionCookies string `json:"session_cookies" secret:"true" help:"登录会话 Cookie（自动维护，含 passport 长期凭证，用于自动续期）"`
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
