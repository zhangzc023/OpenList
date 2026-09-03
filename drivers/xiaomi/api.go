package xiaomi

// 小米云盘接口客户端（依赖已登录的 Account）
// （移植自 mi-drive 的 drivers/xiaomi/api.go，接口逆向自 i.mi.com 网页端 /drive/h5）
//
// 2026-09-02 全面升级到 v2 接口（与网页端一致）：
//   - 列目录：GET  /drive/v2/user/folders/children（parentId 参数化 + 翻页）
//   - 新建目录：POST /drive/v2/user/folders/create（form + serviceToken）
//   - 上传：    POST /drive/v2/user/files/create → 分块上传 → POST /drive/v2/user/files/commit
//   - 直链：    GET  /drive/v2/user/files/{id}（返回 data.storage.downloadUrl）
//   v2 的 POST 统一为 application/x-www-form-urlencoded，且 body 里必须带 serviceToken。

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	log "github.com/sirupsen/logrus"
)

// 分片上传常量（服务端约定：分片必须 4MB，单文件上限 4GB）
const (
	blockSize    = 4 * 1024 * 1024
	maxFileSize  = 4 * 1024 * 1024 * 1024
	maxRedirects = 3
)

// MiApiError 云盘接口错误
type MiApiError struct {
	Code   int
	Msg    string
	Status int
}

func (e *MiApiError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("云盘接口错误（code=%d）", e.Code)
	}
	return e.Msg
}

// API 小米云盘接口客户端
type API struct{ account *Account }

// NewAPI 构造云盘接口客户端
func NewAPI(acc *Account) *API { return &API{account: acc} }

// ---------- 通用请求 ----------

// fetchApi 带 401 自动续期的 API 请求
func (a *API) fetchApi(ctx context.Context, rawURL string, opts Options) (*http.Response, error) {
	return a.fetchApiInner(ctx, rawURL, opts, true)
}

// fetchApiInner 内部实现；allowRenew 控制是否允许触发 serviceToken 自动续期
func (a *API) fetchApiInner(ctx context.Context, rawURL string, opts Options, allowRenew bool) (*http.Response, error) {
	if opts.Headers == nil {
		opts.Headers = map[string]string{}
	}
	opts.Headers["accept"] = "application/json"
	opts.Headers["referer"] = imiHost + "/drive/"
	opts.Ctx = ctx

	res, err := a.account.Client().Request(rawURL, opts, maxRedirects)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		Drain(res)
		// 用 passport 长期会话自动续期后重试一次（避免死循环）
		if allowRenew && a.account.TryRenewServiceToken(ctx) {
			return a.fetchApiInner(ctx, rawURL, opts, false)
		}
		return nil, &MiLoginError{Code: 401, Msg: "登录态已失效，请在管理页重新扫码登录"}
	}
	return res, nil
}

// postForm 以 form-urlencoded 提交（v2 接口风格：serviceToken 放在 body，与网页端一致）。
// 前端封装（i.mi.com /drive/h5 main bundle，模块 iR4f）对所有 POST 自动：
//   content-type: application/x-www-form-urlencoded; charset=UTF-8
//   body 附加 serviceToken（从 cookie 读取）
func (a *API) postForm(ctx context.Context, apiPath string, form url.Values) (*http.Response, error) {
	if form == nil {
		form = url.Values{}
	}
	form.Set("serviceToken", a.account.GetServiceToken())
	return a.fetchApi(ctx, fmt.Sprintf("%s%s", imiHost, apiPath), Options{
		Method: http.MethodPost,
		Body:   strings.NewReader(form.Encode()),
		Headers: map[string]string{
			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
			"origin":       imiHost,
		},
	})
}

// decode 解析响应 JSON 并校验业务结果
func decode(res *http.Response) (map[string]any, error) {
	body, err := readBody(res)
	if err != nil {
		return nil, &MiApiError{Code: -1, Msg: "读取响应失败: " + err.Error()}
	}
	if res.StatusCode != http.StatusOK {
		s := string(body)
		if len(s) > 160 {
			s = s[:160]
		}
		return nil, &MiApiError{Code: -1, Status: res.StatusCode, Msg: fmt.Sprintf("HTTP %d: %s", res.StatusCode, s)}
	}
	parsed, err := parseAnyJson(string(body))
	if err != nil || parsed == nil {
		s := string(body)
		if len(s) > 160 {
			s = s[:160]
		}
		return nil, &MiApiError{Code: -1, Msg: "响应解析失败: " + s}
	}
	if r, ok := parsed["result"]; ok {
		if s, ok := r.(string); ok && s != "ok" {
			return nil, &MiApiError{Code: -1, Msg: s}
		}
		if m, ok := r.(map[string]any); ok {
			// 部分接口用对象描述错误
			if desc, ok := m["description"].(string); ok {
				code := -1
				if c, ok := m["code"].(float64); ok {
					code = int(c)
				}
				return nil, &MiApiError{Code: code, Msg: desc}
			}
		}
	}
	return parsed, nil
}

// normalizeItem 把接口返回的条目转成统一对象模型。
// v2 children 的条目：type=="folder" 为目录，其余（doc/other/txt 等）为文件。
func normalizeItem(it map[string]any) model.Obj {
	isFolder := false
	if t, _ := it["type"].(string); t == "folder" {
		isFolder = true
	}
	if k, _ := it["kind"].(string); k == "folder" {
		isFolder = true
	}
	name := ""
	if v, ok := it["name"].(string); ok {
		name = v
	}
	id := ""
	switch v := it["id"].(type) {
	case string:
		id = v
	case float64:
		id = fmt.Sprintf("%.0f", v)
	}
	var modified, ctime time.Time
	if v := toInt64(it["modifyTime"]); v > 0 {
		modified = time.UnixMilli(v)
	}
	if v := toInt64(it["createTime"]); v > 0 {
		ctime = time.UnixMilli(v)
	}
	return &model.Object{
		ID:       id,
		Name:     name,
		Size:     toInt64(it["size"]),
		IsFolder: isFolder,
		Modified: modified,
		Ctime:    ctime,
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		var out int64
		if _, err := fmt.Sscanf(n, "%d", &out); err == nil {
			return out
		}
	}
	return 0
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ---------- 目录与文件操作（v2）----------

// ListFolder 列出目录内容（根目录 id 为 "0"）。
// v2 接口：GET /drive/v2/user/folders/children?parentId=&pageNo=&limit=&type=&order=&reverse=
// 返回 data.records[]（含 hasMore/allCount），自动翻页拉全。
func (a *API) ListFolder(ctx context.Context, folderID string) ([]model.Obj, error) {
	if folderID == "" {
		folderID = "0"
	}
	out := make([]model.Obj, 0, 100)
	pageNo := 1
	for {
		q := url.Values{}
		q.Set("parentId", folderID)
		q.Set("pageNo", fmt.Sprintf("%d", pageNo))
		q.Set("limit", "100")
		q.Set("type", "")
		q.Set("order", "SERVICE_TIME")
		q.Set("reverse", "true")
		q.Set("ts", fmt.Sprintf("%d", time.Now().UnixMilli()))
		target := fmt.Sprintf("%s/drive/v2/user/folders/children?%s", imiHost, q.Encode())
		res, err := a.fetchApi(ctx, target, Options{Method: http.MethodGet})
		if err != nil {
			return nil, err
		}
		body, err := decode(res)
		if err != nil {
			return nil, err
		}
		data, _ := body["data"].(map[string]any)
		listRaw, _ := data["records"].([]any)
		for _, raw := range listRaw {
			if m, ok := raw.(map[string]any); ok {
				out = append(out, normalizeItem(m))
			}
		}
		hasMore := false
		if v, ok := data["hasMore"].(bool); ok {
			hasMore = v
		}
		if !hasMore || len(listRaw) == 0 {
			break
		}
		if pageNo >= 500 {
			log.Warnf("[xiaomi] 目录条目超过 5 万，停止翻页")
			break
		}
		pageNo++
	}
	return out, nil
}

// GetDownloadURL 获取文件 GET 直链（v2 接口，网页端 /drive/h5 使用）。
// 返回的 downloadUrl 带签名（meta 参数），实测无需 Cookie 即可直接 GET
// 下载，且支持 Range（206 断点续传）。可直接作为 OpenList 的 Link.URL（302 直链），
// 下载流量不经过 OpenList 服务器。
func (a *API) GetDownloadURL(ctx context.Context, fileID string) (string, error) {
	res, err := a.fetchApi(ctx, fmt.Sprintf("%s/drive/v2/user/files/%s",
		imiHost, url.PathEscape(fileID)), Options{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	body, err := decode(res)
	if err != nil {
		return "", err
	}
	data, _ := body["data"].(map[string]any)
	storage, _ := data["storage"].(map[string]any)
	dl, _ := storage["downloadUrl"].(string)
	if dl == "" {
		return "", &MiApiError{Code: -1, Msg: "未获取到下载直链（文件可能已删除）"}
	}
	return dl, nil
}

// CreateFolder 创建目录，返回新目录条目。
// v2 接口：POST /drive/v2/user/folders/create，form: name=&parentId=&serviceToken=
func (a *API) CreateFolder(ctx context.Context, name, parentID string) (*model.Object, error) {
	if parentID == "" {
		parentID = "0"
	}
	form := url.Values{}
	form.Set("name", name)
	form.Set("parentId", parentID)
	res, err := a.postForm(ctx, "/drive/v2/user/folders/create", form)
	if err != nil {
		return nil, err
	}
	body, err := decode(res)
	if err != nil {
		return nil, err
	}
	data, _ := body["data"].(map[string]any)
	return &model.Object{
		ID:       stringValue(data["id"]),
		Name:     firstNonEmpty(stringValue(data["name"]), name),
		IsFolder: true,
	}, nil
}

// DeleteEntry 删除文件或目录（目录级联删除）。
// v2 接口：POST /drive/v2/user/records/filemanager，form: operateType=&operateRecords=&serviceToken=
func (a *API) DeleteEntry(ctx context.Context, id, typ string) error {
	if typ != "folder" {
		typ = "file"
	}
	recs, _ := json.Marshal([]map[string]string{{"id": id, "type": typ}})
	form := url.Values{}
	form.Set("operateType", "DELETE")
	form.Set("operateRecords", string(recs))
	res, err := a.postForm(ctx, "/drive/v2/user/records/filemanager", form)
	if err != nil {
		return err
	}
	_, err = decode(res)
	return err
}

// ---------- 上传（v2）----------

type blockInfo struct {
	Size       int64
	Sha1       string
	Md5        string
	MerkleSha1 string
}

// hashFile 流式计算整文件 sha1 与 4MB 分块 sha1/md5，以及整个文件的 merkle 根。
// 返回的哈希统一为大写 hex（v2 files/create 要求，与网页端一致）。
func hashFile(path string, size int64) (string, []blockInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	// 分块哈希
	blocks, err := computeBlockHashes(path, size)
	if err != nil {
		return "", nil, err
	}
	// 整文件 sha1
	total := sha1.New()
	if _, err := io.CopyBuffer(total, f, make([]byte, 1024*1024)); err != nil {
		return "", nil, err
	}
	fileSha1 := strings.ToUpper(hex.EncodeToString(total.Sum(nil)))

	// merkle 根：单块 = 文件 sha1；多块 = 块 sha1 逐层两两合并
	merkle := fileSha1
	if len(blocks) > 1 {
		hashes := make([][]byte, 0, len(blocks))
		for _, b := range blocks {
			h, _ := hex.DecodeString(strings.ToLower(b.Sha1))
			hashes = append(hashes, h)
		}
		merkle = merkleRoot(hashes)
	}
	for i := range blocks {
		blocks[i].MerkleSha1 = merkle
	}
	return fileSha1, blocks, nil
}

// merkleRoot 模拟网页端 wasm 的 merkle 计算：每轮两两把 sha1 字节拼接后再 sha1，直到剩 1 个。
func merkleRoot(hashes [][]byte) string {
	level := hashes
	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2+1)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				merged := append(append([]byte{}, level[i]...), level[i+1]...)
				h := sha1.Sum(merged)
				next = append(next, h[:])
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}
	return strings.ToUpper(hex.EncodeToString(level[0]))
}

// computeBlockHashes 按 4MB 逐块计算 sha1 与 md5
func computeBlockHashes(path string, size int64) ([]blockInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	blocks := make([]blockInfo, 0, size/blockSize+1)
	remaining := size
	buf := make([]byte, 1024*1024)
	h1 := sha1.New()
	h2 := md5.New()
	var inBlock int64

	for remaining > 0 {
		toRead := int64(len(buf))
		if remaining < toRead {
			toRead = remaining
		}
		n, err := f.Read(buf[:toRead])
		if n > 0 {
			h1.Write(buf[:n])
			h2.Write(buf[:n])
			inBlock += int64(n)
			remaining -= int64(n)
		}
		if inBlock >= blockSize || remaining == 0 {
			if inBlock > 0 {
				blocks = append(blocks, blockInfo{
					Size: inBlock,
					Sha1: strings.ToUpper(hex.EncodeToString(h1.Sum(nil))),
					Md5:  strings.ToUpper(hex.EncodeToString(h2.Sum(nil))),
				})
			}
			h1.Reset()
			h2.Reset()
			inBlock = 0
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(blocks) == 0 && size == 0 {
		blocks = append(blocks, blockInfo{Size: 0, Sha1: strings.ToUpper(hex.EncodeToString(sha1.New().Sum(nil))), Md5: strings.ToUpper(hex.EncodeToString(md5.New().Sum(nil)))})
	}
	return blocks, nil
}

// UploadFile 上传本地文件（v2：4MB 分片 + sha1/merkle 秒传）。
// 流程（与网页端一致，已实测验证）：
//   1. POST /drive/v2/user/files/create  → data.uploadId / data.exists / data.kss{node_urls,file_meta,block_metas}
//   2. 命中秒传（exists=true）→ 直接返回 data.id，不提交
//   3. 逐分片 POST {node}/upload_block_chunk?chunk_pos=0&&file_meta=..&block_meta=..（body=分片二进制）→ {commit_meta}
//      （block.is_existed==1 的块直接用已有 commit_meta，跳过上传）
//   4. POST /drive/v2/user/files/commit → data.id
func (a *API) UploadFile(ctx context.Context, localPath, name, parentID string, onProgress func(loaded, total int64)) (*model.Object, error) {
	if parentID == "" {
		parentID = "0"
	}
	fname := name
	if fname == "" {
		fname = filepath.Base(localPath)
	}
	st, err := os.Stat(localPath)
	if err != nil {
		return nil, fmt.Errorf("读取待上传文件失败: %w", err)
	}
	size := st.Size()
	if size > maxFileSize {
		return nil, fmt.Errorf("单文件超过 4GB 上限")
	}

	// 1. 哈希
	fileSha1, blocks, err := hashFile(localPath, size)
	if err != nil {
		return nil, fmt.Errorf("计算文件哈希失败: %w", err)
	}

	now := time.Now().UnixMilli()
	data := map[string]any{
		"fileName":        fname,
		"size":            size,
		"sha1":            fileSha1,
		"mimeType":        mimeTypeOf(fname),
		"channel":         "PC",
		"parentId":        parentID,
		"localCreateTime": now,
		"localModifyTime": now,
		"exifInfo":        map[string]any{},
	}
	blockInfos := make([]map[string]any, 0, len(blocks))
	for _, b := range blocks {
		blockInfos = append(blockInfos, map[string]any{
			"sha1":       b.Sha1,
			"md5":        b.Md5,
			"size":       b.Size,
			"merkleSha1": b.MerkleSha1,
		})
	}
	kss := map[string]any{
		"block_infos": blockInfos,
		"splitSize":   blockSize,
	}
	dataJSON, _ := json.Marshal(data)
	kssJSON, _ := json.Marshal(kss)

	// 2. 初始化
	createForm := url.Values{}
	createForm.Set("data", string(dataJSON))
	createForm.Set("kss", string(kssJSON))
	createRes, err := a.postForm(ctx, "/drive/v2/user/files/create", createForm)
	if err != nil {
		return nil, err
	}
	createBody, err := decode(createRes)
	if err != nil {
		return nil, err
	}
	cd, _ := createBody["data"].(map[string]any)
	if exists, _ := cd["exists"].(bool); exists {
		// 秒传命中：data.id 即新文件 id，直接完成
		log.Infof("[xiaomi] 文件 %s 命中秒传", fname)
		if onProgress != nil {
			onProgress(size, size)
		}
		return &model.Object{
			ID:       stringValue(cd["id"]),
			Name:     fname,
			Size:     size,
			IsFolder: false,
			Modified: time.Now(),
		}, nil
	}

	uploadID := stringValue(cd["uploadId"])
	if uploadID == "" {
		return nil, &MiApiError{Code: -1, Msg: "上传初始化失败：未返回 uploadId"}
	}
	kssData, _ := cd["kss"].(map[string]any)
	nodeURL := ""
	if urls, ok := kssData["node_urls"].([]any); ok && len(urls) > 0 {
		nodeURL, _ = urls[0].(string)
	}
	fileMeta := stringValue(kssData["file_meta"])
	blockMetas, _ := kssData["block_metas"].([]any)
	if nodeURL == "" || fileMeta == "" || len(blockMetas) == 0 {
		s, _ := json.Marshal(createBody)
		if len(s) > 300 {
			s = s[:300]
		}
		return nil, &MiApiError{Code: -1, Msg: "上传初始化失败：" + string(s)}
	}

	// 3. 逐分片上传
	fd, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer fd.Close()

	commitMetas := make([]map[string]any, 0, len(blockMetas))
	for i, rawMeta := range blockMetas {
		bm, _ := rawMeta.(map[string]any)
		// 块已存在（秒传块）：直接用已有 commit_meta
		if v, ok := bm["is_existed"].(float64); ok && int(v) == 1 {
			if cm, ok := bm["commit_meta"].(string); ok && cm != "" {
				commitMetas = append(commitMetas, map[string]any{"commit_meta": cm})
				continue
			}
		}
		blockMeta := stringValue(bm["block_meta"])
		chunk := make([]byte, blocks[i].Size)
		if _, err := io.ReadFull(fd, chunk); err != nil {
			return nil, &MiApiError{Code: -1, Msg: fmt.Sprintf("读取分片 %d 失败: %v", i, err)}
		}
		target := fmt.Sprintf("%s/upload_block_chunk?chunk_pos=0&&file_meta=%s&block_meta=%s",
			strings.TrimRight(nodeURL, "/"), fileMeta, blockMeta)
		res, err := a.account.Client().Fetch(target, Options{
			Ctx:    ctx,
			Method: http.MethodPost,
			Body:   bytes.NewReader(chunk),
			Headers: map[string]string{
				"content-type": "application/octet-stream",
				"origin":       imiHost,
				"referer":      imiHost + "/",
			},
		})
		if err != nil {
			return nil, &MiApiError{Code: -1, Msg: fmt.Sprintf("分片 %d 上传失败: %v", i, err)}
		}
		body, _ := readBody(res)
		if res.StatusCode != http.StatusOK {
			Drain(res)
			if len(body) > 160 {
				body = body[:160]
			}
			return nil, &MiApiError{Code: res.StatusCode, Msg: fmt.Sprintf("分片 %d 上传失败（HTTP %d）: %s", i, res.StatusCode, string(body))}
		}
		Drain(res)
		parsed, err := parseAnyJson(string(body))
		if err != nil {
			return nil, &MiApiError{Code: -1, Msg: fmt.Sprintf("分片 %d 响应解析失败", i)}
		}
		cm := stringValue(parsed["commit_meta"])
		if cm == "" {
			return nil, &MiApiError{Code: -1, Msg: fmt.Sprintf("分片 %d 未返回 commit_meta", i)}
		}
		commitMetas = append(commitMetas, map[string]any{"commit_meta": cm})
		if onProgress != nil {
			loaded := int64(i+1) * blockSize
			if loaded > size {
				loaded = size
			}
			onProgress(loaded, size)
		}
	}

	// 4. 提交
	commitMetasJSON, _ := json.Marshal(commitMetas)
	commitForm := url.Values{}
	commitForm.Set("uploadId", uploadID)
	commitForm.Set("file_meta", fileMeta)
	commitForm.Set("commit_metas", string(commitMetasJSON))
	commitForm.Set("parentId", parentID)
	commitRes, err := a.postForm(ctx, "/drive/v2/user/files/commit", commitForm)
	if err != nil {
		return nil, err
	}
	commitBody, err := decode(commitRes)
	if err != nil {
		return nil, err
	}
	dd, _ := commitBody["data"].(map[string]any)
	newID := stringValue(dd["id"])

	return &model.Object{
		ID:       newID,
		Name:     fname,
		Size:     size,
		IsFolder: false,
		Modified: time.Now(),
	}, nil
}

// mimeTypeOf 按扩展名推断 MIME（v2 files/create 的 data.mimeType）
func mimeTypeOf(name string) string {
	if m := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); m != "" {
		// 去掉 charset 后缀
		if i := strings.IndexByte(m, ';'); i >= 0 {
			m = strings.TrimSpace(m[:i])
		}
		return m
	}
	return "application/octet-stream"
}

// ---------- 小工具 ----------

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
