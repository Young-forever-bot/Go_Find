package whois

// miit.go —— 工信部 ICP 备案官方接口直查。
// 流程: auth(authKey=md5("testtest"+秒级时间戳)) → 获取 token
//   → image/getCheckImagePoint 获取滑块拼图 → 方差扫描定位缺口 x
//   → image/checkImage 校验获得 sign → icpAbbreviateInfo/queryByCondition 查询。
// 该流程不含外部依赖，缺口检测用积分图方差最小值，对官方拼图验证码实测有效。

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gofind/internal/model"
)

const (
	miitBase   = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/"
	miitOrigin = "https://beian.miit.gov.cn/"
	miitRefer  = "https://beian.miit.gov.cn/"
	miitUA     = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
	jsonCT     = "application/json;charset=UTF-8"
	formCT     = "application/x-www-form-urlencoded;charset=UTF-8"
)

// errNoICPRecord 表示权威数据源明确返回"无备案记录"。
var errNoICPRecord = errors.New("no icp record")

type miitEnvelope struct {
	Success bool            `json:"success"`
	Code    int             `json:"code"`
	Msg     string          `json:"msg"`
	Params  json.RawMessage `json:"params"`
}

type miitAuthParams struct {
	Bussiness string `json:"bussiness"`
}

type miitCaptchaParams struct {
	UUID      string `json:"uuid"`
	BigImage  string `json:"bigImage"`
	SmallImage string `json:"smallImage"`
	Height    int    `json:"height"`
}

// miitQueryICP 直查工信部备案库。域名未备案时返回 errNoICPRecord。
func miitQueryICP(ctx context.Context, domain string, timeout time.Duration) (*model.ICPInfo, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if d, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(d)
	}

	// 1. auth → token
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	authKey := fmt.Sprintf("%x", md5.Sum([]byte("testtest"+ts)))
	form := url.Values{"authKey": {authKey}, "timeStamp": {ts}}
	var authEnv miitEnvelope
	if err := miitPost(ctx, client, "auth", formCT, strings.NewReader(form.Encode()), "0", nil, &authEnv); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	var authP miitAuthParams
	if err := json.Unmarshal(authEnv.Params, &authP); err != nil || authP.Bussiness == "" {
		return nil, fmt.Errorf("auth 未返回 token: %s", authEnv.Msg)
	}
	token := authP.Bussiness

	// 2. 获取滑块拼图
	var capEnv miitEnvelope
	if err := miitPost(ctx, client, "image/getCheckImagePoint", jsonCT,
		strings.NewReader(`{"clientUid":"gofind"}`), token, nil, &capEnv); err != nil {
		return nil, fmt.Errorf("获取验证码: %w", err)
	}
	var capP miitCaptchaParams
	if err := json.Unmarshal(capEnv.Params, &capP); err != nil || capP.UUID == "" {
		return nil, fmt.Errorf("验证码响应异常: %s", capEnv.Msg)
	}

	// 3. 检测缺口位置
	gapX, err := solveGap(capP.BigImage)
	if err != nil {
		return nil, fmt.Errorf("识别滑块缺口: %w", err)
	}

	// 4. 校验滑块 → sign
	checkBody := fmt.Sprintf(`{"key":%q,"value":%q}`, capP.UUID, strconv.Itoa(gapX))
	var checkEnv miitEnvelope
	if err := miitPost(ctx, client, "image/checkImage", jsonCT, strings.NewReader(checkBody), token, nil, &checkEnv); err != nil {
		return nil, fmt.Errorf("滑块校验: %w", err)
	}
	var sign string
	if err := json.Unmarshal(checkEnv.Params, &sign); err != nil || sign == "" {
		if checkEnv.Msg != "" {
			return nil, fmt.Errorf("滑块校验失败: %s", checkEnv.Msg)
		}
		return nil, fmt.Errorf("滑块校验未返回 sign")
	}

	// 5. 查询备案
	qBody := fmt.Sprintf(`{"pageNum":"","pageSize":"","unitName":%q,"serviceType":1,"contentType":""}`, domain)
	hdrs := map[string]string{"uuid": capP.UUID, "sign": sign}
	var qEnv miitEnvelope
	if err := miitPost(ctx, client, "icpAbbreviateInfo/queryByCondition", jsonCT, strings.NewReader(qBody), token, hdrs, &qEnv); err != nil {
		// 403 多为 WAF 频控，稍候重试一次
		time.Sleep(2 * time.Second)
		if err2 := miitPost(ctx, client, "icpAbbreviateInfo/queryByCondition", jsonCT, strings.NewReader(qBody), token, hdrs, &qEnv); err2 != nil {
			return nil, fmt.Errorf("备案查询: %v / 重试: %v", err, err2)
		}
	}
	if !qEnv.Success || qEnv.Code != 200 {
		msg := qEnv.Msg
		if msg == "" {
			msg = "响应异常"
		}
		return nil, fmt.Errorf("备案查询: %s", msg)
	}

	// params.list 容错解析
	var qParams struct {
		List []map[string]any `json:"list"`
	}
	if err := json.Unmarshal(qEnv.Params, &qParams); err != nil {
		return nil, fmt.Errorf("备案响应解析: %w", err)
	}
	if len(qParams.List) == 0 {
		return nil, errNoICPRecord
	}
	row := qParams.List[0]
	return &model.ICPInfo{
		Name: miitStr(row, "unitName", "unit_name", "companyName"),
		Type: miitStr(row, "natureName", "nature_name", "entType"),
		ICP:  firstNonEmpty(miitStr(row, "serviceLicence", "service_id"), miitStr(row, "mainLicence", "mainLicNo")),
		Site: firstNonEmpty(miitStr(row, "domain", "mainDomain"), miitStr(row, "homeUrl", "mainPage")),
		Time: miitStr(row, "updateRecordTime", "update_record_time", "auditTime"),
	}, nil
}

func miitPost(ctx context.Context, client *http.Client, path, ctype string, body io.Reader, token string, hdrs map[string]string, out *miitEnvelope) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, miitBase+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", miitUA)
	req.Header.Set("Origin", miitOrigin)
	req.Header.Set("Referer", miitRefer)
	if token != "" {
		req.Header.Set("token", token)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", ctype)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("响应解析: %w", err)
	}
	return nil
}

// solveGap 在背景图中定位拼图缺口：缺口是半透明纯色块（灰度方差≈0），
// 用积分图计算全图所有窗口的方差，最小者即缺口左上角。
func solveGap(b64Image string) (int, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Image)
	if err != nil {
		return 0, err
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	b := img.Bounds()
	W, H := b.Dx(), b.Dy()
	if W < 24 || H < 24 {
		return 0, fmt.Errorf("验证码图片过小: %dx%d", W, H)
	}
	gray := make([]int64, W*H)
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			gray[y*W+x] = int64((r>>8)+(g>>8)+(bl>>8)) / 3
		}
	}
	// 积分图（和 与 平方和）
	sat := make([]int64, (W+1)*(H+1))
	sat2 := make([]int64, (W+1)*(H+1))
	for y := 0; y < H; y++ {
		rowSum, rowSum2 := int64(0), int64(0)
		for x := 0; x < W; x++ {
			v := gray[y*W+x]
			rowSum += v
			rowSum2 += v * v
			sat[(y+1)*(W+1)+x+1] = sat[y*(W+1)+x+1] + rowSum
			sat2[(y+1)*(W+1)+x+1] = sat2[y*(W+1)+x+1] + rowSum2
		}
	}
	winW, winH := 56, 56
	if W < winW*2 {
		winW = W / 2
	}
	if H < winH*2 {
		winH = H / 2
	}
	bestVar, bestX := int64(-1), 0
	n := int64(winW) * int64(winH)
	for y0 := 0; y0+winH <= H; y0 += 2 {
		for x0 := 0; x0+winW <= W; x0 += 2 {
			s1 := sat[(y0+winH)*(W+1)+x0+winW] - sat[y0*(W+1)+x0+winW] - sat[(y0+winH)*(W+1)+x0] + sat[y0*(W+1)+x0]
			s2 := sat2[(y0+winH)*(W+1)+x0+winW] - sat2[y0*(W+1)+x0+winW] - sat2[(y0+winH)*(W+1)+x0] + sat2[y0*(W+1)+x0]
			mean := s1 / n
			v := s2/n - mean*mean
			if bestVar < 0 || v < bestVar {
				bestVar = v
				bestX = x0
			}
		}
	}
	return bestX, nil
}

func miitStr(row map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := row[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
