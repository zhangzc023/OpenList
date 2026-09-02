package xiaomi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// XiaomiDrive 小米云盘驱动器：把 Account + API 包装成统一 Driver 接口。
// 小米云盘接口基于 id，外部接口基于 path，这里用 idCache 做 path→id 的换算缓存。
type XiaomiDrive struct {
	model.Storage
	Addition

	client  *httpClient
	account *Account
	api     *API
	idCache *idCache
	qrParam *qrInfo

	storageConfig driver.Config
}

// ---------- id 缓存（path → {id, type}）----------

type idInfo struct {
	id  string
	typ string // file | folder
}

type idCache struct {
	mu sync.RWMutex
	m  map[string]idInfo
}

func newIDCache() *idCache { return &idCache{m: map[string]idInfo{}} }

func (c *idCache) get(p string) (idInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[p]
	return v, ok
}

func (c *idCache) set(p string, info idInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[p] = info
}

// delete 删除某路径及其所有后代（父目录变更后失效）
func (c *idCache) delete(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix = NormalizePath(prefix)
	delete(c.m, prefix)
	for k := range c.m {
		if k == prefix || strings.HasPrefix(k, prefix+"/") {
			delete(c.m, k)
		}
	}
}

// ---------- Driver 接口 ----------

func (d *XiaomiDrive) Config() driver.Config {
	if d.storageConfig.Name == "" {
		d.storageConfig = config
	}
	return d.storageConfig
}

func (d *XiaomiDrive) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *XiaomiDrive) Init(ctx context.Context) error {
	d.storageConfig = config
	if d.client == nil {
		d.client = NewHTTPClient(NewJar())
	}
	if d.account == nil {
		d.account = NewAccount(d.client)
	}
	d.api = NewAPI(d.account)
	if d.idCache == nil {
		d.idCache = newIDCache()
	}

	// 1) 尝试恢复已保存的登录会话
	if d.Addition.SessionCookies != "" {
		var cookies []Cookie
		if err := json.Unmarshal([]byte(d.Addition.SessionCookies), &cookies); err == nil && len(cookies) > 0 {
			d.account.RestoreCookies(cookies)
			if ok, _ := d.account.CheckDrive(ctx); ok {
				if err := d.account.FinishLogin(); err != nil {
					log.Warnf("[xiaomi] 恢复会话后收尾失败: %v", err)
				} else {
					return nil
				}
			}
		}
		// 会话失效，清除并继续走扫码/Cookie
		d.Addition.SessionCookies = ""
		d.account.Reset()
	}

	// 2) Cookie 登录
	if d.Addition.Cookie != "" {
		if err := d.account.LoginWithCookie(ctx, d.Addition.Cookie); err != nil {
			return err
		}
		d.saveSession()
		return nil
	}

	// 3) 扫码登录（返回 need verify，前端渲染二维码）
	return d.qrLogin(ctx)
}

func (d *XiaomiDrive) Drop(ctx context.Context) error {
	if d.account != nil {
		d.account.Stop()
	}
	return nil
}

// Ready 是否已登录
func (d *XiaomiDrive) Ready() bool {
	return d.account != nil && d.account.Ready()
}

// saveSession 把当前登录态序列化保存到 Addition 并持久化
func (d *XiaomiDrive) saveSession() {
	cookies := d.account.SerializeCookies()
	if len(cookies) == 0 {
		return
	}
	b, err := json.Marshal(cookies)
	if err != nil {
		return
	}
	d.account.mu.Lock()
	uid := d.account.UserID
	did := d.account.DeviceID
	token := d.account.ServiceToken
	d.account.mu.Unlock()

	d.Addition.SessionCookies = string(b)
	d.Addition.UserID = uid
	d.Addition.DeviceID = did
	d.Addition.ServiceToken = token
	op.MustSaveDriverStorage(d)
}

// ---------- 扫码登录（OpenList 机制：错误返回 need verify，前端渲染 HTML）----------
//
// 重要：OpenList 每次保存存储都会 driverNew() 重建驱动实例（见 internal/op/storage.go
// 的 initStorage），因此不能依赖实例内存保存二维码状态。这里创建二维码后立即启动
// 后台 goroutine 持续长轮询（对齐原项目前端行为）：扫码确认后自动完成登录并把会话
// 持久化到数据库。用户扫码后无论何时再点「保存」，新实例都能从 Addition 恢复会话。

func (d *XiaomiDrive) qrLogin(ctx context.Context) error {
	info, err := d.account.CreateQRCode(ctx)
	if err != nil {
		return err
	}
	d.qrParam = info
	d.startQrPoll(info)
	return d.genQRCodeHTML("请用小米手机或平板扫码登录。扫码确认后将自动完成登录，然后请点击页面底部「保存」")
}

// startQrPoll 后台持续长轮询 lp，直到扫码确认完成登录或二维码过期
func (d *XiaomiDrive) startQrPoll(info *qrInfo) {
	go func() {
		timeout := info.Timeout
		if timeout <= 0 {
			timeout = 300
		}
		pollCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+30)*time.Second)
		defer cancel()

		for {
			select {
			case <-pollCtx.Done():
				log.Warn("[xiaomi] 二维码轮询超时，已停止（请重新保存刷新二维码）")
				return
			default:
			}
			status := d.account.PollQRStatus(pollCtx, info.Lp)
			switch status.Status {
			case "confirmed":
				log.Info("[xiaomi] 扫码已确认，正在完成登录")
				if err := d.account.FinishQrLogin(pollCtx, status.Location); err != nil {
					log.Warnf("[xiaomi] 扫码登录失败: %v", err)
					return
				}
				d.saveSession()
				log.Info("[xiaomi] 扫码登录成功，会话已保存，请在管理页再次保存以完成挂载")
				return
			case "waiting":
				// 单次长轮询超时，续轮询
				continue
			default: // expired / error
				log.Warnf("[xiaomi] 二维码轮询结束: status=%s desc=%s err=%s", status.Status, status.Desc, status.Error)
				return
			}
		}
	}()
}

func (d *XiaomiDrive) genQRCodeHTML(text string) error {
	qrTemplate := `<body>
	state: %s
	<br><img src="%s" style="max-width:256px;max-height:256px;"/>
	<br>扫码后请点击页面底部的「保存」按钮完成登录
</body>`
	page := fmt.Sprintf(qrTemplate, text, d.qrParam.QrDataUri)
	return fmt.Errorf("need verify: \n%s", page)
}

// ---------- path → id ----------

// GetRoot implements driver.GetRooter：返回小米云盘根目录对象（根 ID 恒为 "0"）。
// OpenList 访问挂载根路径 "/" 时必须能拿到根对象，否则报
// "please implement GetRooter or IRootPath or IRootId interface"。
func (d *XiaomiDrive) GetRoot(ctx context.Context) (model.Obj, error) {
	return &model.Object{
		ID:       "0",
		Path:     "/",
		Name:     "root",
		Modified: d.Modified,
		IsFolder: true,
		Mask:     model.Locked,
	}, nil
}

// resolveID 把外部虚拟路径换算成小米云盘的 folderId / fileId。
// 返回 (id, type, err)。中间段是文件则报错；找不到报 ObjectNotFound。
func (d *XiaomiDrive) resolveID(ctx context.Context, p string) (string, string, error) {
	p = NormalizePath(p)
	if p == "/" {
		return "0", "folder", nil
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "0"
	curPath := ""
	for i, part := range parts {
		if part == "" {
			continue
		}
		next := curPath + "/" + part
		if info, ok := d.idCache.get(next); ok {
			if info.typ == "file" && i < len(parts)-1 {
				return "", "", fmt.Errorf("%s 不是目录", next)
			}
			if info.typ == "file" {
				return info.id, "file", nil
			}
			cur = info.id
			curPath = next
			continue
		}
		items, err := d.api.ListFolder(ctx, cur)
		if err != nil {
			return "", "", err
		}
		var found model.Obj
		foundOK := false
		for j := range items {
			if items[j].GetName() == part {
				found = items[j]
				foundOK = true
				break
			}
		}
		if !foundOK {
			return "", "", errs.ObjectNotFound
		}
		if !found.IsDir() {
			if i < len(parts)-1 {
				return "", "", fmt.Errorf("%s 不是目录", next)
			}
			d.idCache.set(next, idInfo{id: found.GetID(), typ: "file"})
			return found.GetID(), "file", nil
		}
		d.idCache.set(next, idInfo{id: found.GetID(), typ: "folder"})
		cur = found.GetID()
		curPath = next
	}
	return cur, "folder", nil
}

// ---------- 文件操作 ----------

func (d *XiaomiDrive) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if !d.Ready() {
		return nil, fmt.Errorf("小米云盘未登录，请在管理页扫码登录")
	}
	dirPath := dir.GetPath()
	if dirPath == "" {
		dirPath = "/"
	}
	folderID, typ, err := d.resolveID(ctx, dirPath)
	if err != nil {
		return nil, err
	}
	if typ == "file" {
		return nil, errs.NotFolder
	}
	items, err := d.api.ListFolder(ctx, folderID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if obj, ok := items[i].(*model.Object); ok {
			obj.Path = JoinPath(dirPath, obj.Name)
		}
	}
	return items, nil
}

func (d *XiaomiDrive) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if !d.Ready() {
		return nil, fmt.Errorf("小米云盘未登录，请在管理页扫码登录")
	}
	// v2 接口返回 GET 直链（带 meta 签名，无需 Cookie，支持 Range 206）。
	// OpenList 直接 302 到该 URL，下载流量走小米 CDN，不经 OpenList 服务器。
	dlURL, err := d.api.GetDownloadURL(ctx, file.GetID())
	if err != nil {
		return nil, err
	}
	return &model.Link{URL: dlURL}, nil
}

func (d *XiaomiDrive) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) (model.Obj, error) {
	if !d.Ready() {
		return nil, fmt.Errorf("小米云盘未登录，请在管理页扫码登录")
	}
	parentPath := parentDir.GetPath()
	if parentPath == "" {
		parentPath = "/"
	}
	pid, _, err := d.resolveID(ctx, parentPath)
	if err != nil {
		return nil, err
	}
	obj, err := d.api.CreateFolder(ctx, dirName, pid)
	if err != nil {
		return nil, err
	}
	obj.Path = JoinPath(parentPath, dirName)
	d.idCache.delete(parentPath)
	return obj, nil
}

func (d *XiaomiDrive) Remove(ctx context.Context, obj model.Obj) error {
	if !d.Ready() {
		return fmt.Errorf("小米云盘未登录，请在管理页扫码登录")
	}
	typ := "file"
	if obj.IsDir() {
		typ = "folder"
	}
	if err := d.api.DeleteEntry(ctx, obj.GetID(), typ); err != nil {
		return err
	}
	d.idCache.delete(NormalizePath(obj.GetPath()))
	return nil
}

func (d *XiaomiDrive) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	if !d.Ready() {
		return nil, fmt.Errorf("小米云盘未登录，请在管理页扫码登录")
	}
	if stream.GetName() == "" {
		return nil, fmt.Errorf("文件名为空")
	}

	// 先落到本地临时文件（哈希与分片上传需要可 seek 的文件）
	tmpF, err := os.CreateTemp(conf.Conf.TempDir, "file-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tmpF.Close()
		_ = os.Remove(tmpF.Name())
	}()
	// 落到本地临时文件的 copy 不展示进度，但 CopyWithCtx 要求 progress 非 nil
	//（文件非空时它会直接调用 progress，传 nil 会触发空指针 panic）
	if err := utils.CopyWithCtx(ctx, tmpF, stream, stream.GetSize(), func(float64) {}); err != nil {
		return nil, err
	}
	if err := tmpF.Sync(); err != nil {
		return nil, err
	}

	parentPath := dstDir.GetPath()
	if parentPath == "" {
		parentPath = "/"
	}
	pid, _, err := d.resolveID(ctx, parentPath)
	if err != nil {
		return nil, err
	}

	obj, err := d.api.UploadFile(ctx, tmpF.Name(), stream.GetName(), pid, func(loaded, total int64) {
		if total > 0 && up != nil {
			up(float64(loaded) * 100 / float64(total))
		}
	})
	if err != nil {
		return nil, err
	}
	obj.Path = JoinPath(parentPath, stream.GetName())
	d.idCache.delete(parentPath)
	return obj, nil
}

var _ driver.Driver = (*XiaomiDrive)(nil)
var _ driver.GetRooter = (*XiaomiDrive)(nil)
