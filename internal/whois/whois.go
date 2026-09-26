// Package whois 实现 WHOIS 查询（IANA → 注册局 referral，端口 43 原生协议）
// 与 ICP 备案查询（工信部官方直查 + 多源 HTTP API 并发竞速，支持自定义数据源）。
package whois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gofind/internal/model"
)

// Options WHOIS/备案查询参数。
type Options struct {
	Domains     []string
	Timeout     time.Duration // 单次查询超时
	DoWhois     bool
	DoICP       bool
	Workers     int
	ICPEndpoint string // 自定义备案查询 API，需含 {domain} 占位符，返回 JSON；留空用内置源
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

// 内置备案查询源，按序尝试直到某个源返回有效备案信息。
var builtinICPEndpoints = []string{
	"https://api.vvhan.com/api/icp?url={domain}",
	"https://api.pearktrue.cn/api/icp/?domain={domain}",
	"https://api.52vmy.cn/api/query/icp?url={domain}",
}

var (
	reReferServer = regexp.MustCompile(`(?im)^\s*(?:registrar\s+)?(?:refer|whois(?:\s+server)?)\s*:\s*([a-z0-9.\-]+\.[a-z]{2,})`)
	reRegistrar   = regexp.MustCompile(`(?im)^\s*Registrar\s*:\s*(.+?)[ \t]*$`)
	reCreated     = regexp.MustCompile(`(?im)^\s*(?:Creation Date|Created Date|Created|Created On|Registered On|Registration Time|Registration Date)\s*:\s*(.+?)[ \t]*$`)
	reExpiry      = regexp.MustCompile(`(?im)^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|Expiration Time|Expiry)\s*:\s*(.+?)[ \t]*$`)
	reStatus      = regexp.MustCompile(`(?im)^\s*(?:Domain\s+)?Status\s*:\s*(\S+)`)
	reNameServer  = regexp.MustCompile(`(?im)^\s*(?:Name Server|Nameserver|nserver|Name Servers)\s*:\s*(\S+)`)
	reICPNumber   = regexp.MustCompile(`[\p{Han}]{1,8}ICP[证备]?\S{0,12}号(-\d+)?`)
)

// 常见二级公共后缀（无 PSL 库时的实用近似），用于提取注册域。
var twoLevelTLDs = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"ac.cn": true, "mil.cn": true, "co.uk": true, "org.uk": true, "gov.uk": true,
	"ac.uk": true, "co.jp": true, "or.jp": true, "ne.jp": true, "com.hk": true,
	"org.hk": true, "edu.hk": true, "gov.hk": true, "com.tw": true, "org.tw": true,
	"com.au": true, "net.au": true, "org.au": true, "com.sg": true, "com.br": true,
	"co.kr": true, "or.kr": true, "com.ru": true, "co.in": true, "co.nz": true,
	"org.nz": true, "com.mx": true, "co.th": true, "com.tr": true, "co.za": true,
}

var icpClient = &http.Client{}

// Run 执行查询，结束返回 nil 或错误。
func Run(ctx context.Context, o Options, emit Emitter) error {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Workers <= 0 {
		o.Workers = 20
	}
	if o.Workers > 200 {
		o.Workers = 200
	}
	if len(o.Domains) == 0 {
		return fmt.Errorf("目标为空")
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}

	total := len(o.Domains)
	mode := []string{}
	if o.DoWhois {
		mode = append(mode, "whois")
	}
	if o.DoICP {
		mode = append(mode, "ICP备案")
	}
	logf("info", "开始 WHOIS/备案查询: %d 个域名 (方式: %s)", total, strings.Join(mode, " + "))

	var done atomic.Int64
	jobs := make(chan string)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for d := range jobs {
			res := queryDomain(ctx, d, o)
			emit(model.Event{Type: "result", Data: res})
			n := int(done.Add(1))
			emit(model.Event{Type: "progress", Data: model.Progress{Done: n, Total: total}})
		}
	}
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
	outer:
		for _, d := range o.Domains {
			select {
			case <-ctx.Done():
				break outer
			default:
			}
			select {
			case <-ctx.Done():
				break outer
			case jobs <- d:
			}
		}
	}()
	wg.Wait()
	logf("info", "WHOIS/备案查询完成: %d/%d", total, total)
	return nil
}

// queryDomain 查询单个域名，whois 与 ICP 两部分互相独立、失败互不影响。
func queryDomain(ctx context.Context, domain string, o Options) model.WhoisResult {
	res := model.WhoisResult{Domain: domain, Registrable: registrableDomain(domain)}
	if o.DoWhois {
		raw, err := whoisQuery(ctx, res.Registrable, o.Timeout)
		if err != nil {
			res.WhoisError = err.Error()
		} else {
			res.Raw = truncate(raw, 4000)
			parseWhois(raw, &res)
		}
	}
	if o.DoICP {
		info, err := icpQuery(ctx, res.Registrable, o.ICPEndpoint, o.Timeout)
		switch {
		case errors.Is(err, errNoICPRecord):
			res.ICPError = "工信部备案库无该域名的备案记录"
		case err != nil:
			res.ICPError = err.Error()
		default:
			res.ICP = info
		}
	}
	return res
}

// whoisQuery 先查 IANA 拿注册局 whois 服务器，再查注册局。
func whoisQuery(ctx context.Context, domain string, timeout time.Duration) (string, error) {
	first, err := queryServer(ctx, "whois.iana.org:43", domain, timeout)
	if err != nil {
		return "", fmt.Errorf("IANA 查询失败: %w", err)
	}
	server := extractWhoisServer(first)
	if server == "" {
		return first, nil
	}
	if !strings.Contains(server, ":") {
		server += ":43"
	}
	second, err := queryServer(ctx, server, domain, timeout)
	if err != nil {
		return first, fmt.Errorf("%s 查询失败: %w", server, err)
	}
	return second, nil
}

// queryServer 通过端口 43 发送 WHOIS 查询并读取全部响应。
func queryServer(ctx context.Context, addr, query string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 128<<10))
	if err != nil && len(data) == 0 {
		return "", err
	}
	return string(data), nil
}

func extractWhoisServer(text string) string {
	if m := reReferServer.FindStringSubmatch(text); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// parseWhois 从原始 WHOIS 文本提取结构化字段（兼容 VeriSign/CNNIC 等常见格式）。
func parseWhois(raw string, res *model.WhoisResult) {
	if m := reRegistrar.FindStringSubmatch(raw); m != nil {
		res.Registrar = strings.TrimSpace(m[1])
	}
	if m := reCreated.FindStringSubmatch(raw); m != nil {
		res.CreationDate = strings.TrimSpace(m[1])
	}
	if m := reExpiry.FindStringSubmatch(raw); m != nil {
		res.ExpiryDate = strings.TrimSpace(m[1])
	}
	if m := reStatus.FindStringSubmatch(raw); m != nil {
		res.Status = strings.TrimSpace(m[1])
	}
	seen := map[string]struct{}{}
	for _, m := range reNameServer.FindAllStringSubmatch(raw, -1) {
		ns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(m[1]), "."))
		if ns == "" {
			continue
		}
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		res.NameServers = append(res.NameServers, ns)
		if len(res.NameServers) >= 8 {
			break
		}
	}
}

// icpQuery 并发竞速全部备案源（工信部官方 + 内置 HTTP 源 + 自定义源），
// 任一返回有效备案信息即成功；工信部明确返回"无备案记录"时立即返回该权威结论。
func icpQuery(ctx context.Context, domain, custom string, timeout time.Duration) (*model.ICPInfo, error) {
	endpoints := make([]string, 0, len(builtinICPEndpoints)+1)
	if custom != "" {
		if !strings.Contains(custom, "{domain}") {
			return nil, fmt.Errorf("自定义备案 API 需包含 {domain} 占位符")
		}
		endpoints = append(endpoints, custom)
	}
	endpoints = append(endpoints, builtinICPEndpoints...)

	// 并发竞速：工信部官方源（权威，最高优先级）+ 各 HTTP 源，任一成功即返回
	type result struct {
		info       *model.ICPInfo
		err        error
		src        string
		definitive bool // 工信部明确无备案记录
	}
	ch := make(chan result, len(endpoints)+1)

	go func() {
		info, err := miitQueryICP(ctx, domain, timeout)
		if err != nil && errors.Is(err, errNoICPRecord) {
			ch <- result{err: err, src: "工信部", definitive: true}
			return
		}
		ch <- result{info: info, err: err, src: "工信部"}
	}()
	for _, tpl := range endpoints {
		go func(tpl string) {
			info, err := fetchICPHTTPEndpoint(ctx, tpl, domain, timeout)
			ch <- result{info: info, err: err, src: hostOf(tpl)}
		}(tpl)
	}

	var errs []string
	for i := 0; i < len(endpoints)+1; i++ {
		r := <-ch
		if r.definitive {
			return nil, errNoICPRecord
		}
		if r.info != nil {
			return r.info, nil
		}
		if r.err != nil {
			errs = append(errs, r.src+": "+r.err.Error())
		}
	}
	msg := strings.Join(errs, "；")
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return nil, fmt.Errorf("%s", msg)
}

// fetchICPHTTPEndpoint 请求单个 HTTP 备案数据源并做容错解析。
func fetchICPHTTPEndpoint(ctx context.Context, tpl, domain string, timeout time.Duration) (*model.ICPInfo, error) {
	u := strings.ReplaceAll(tpl, "{domain}", url.QueryEscape(domain))
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GoFind/1.0")
	resp, err := icpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if rerr != nil {
		return nil, rerr
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if info := parseICPJSON(body); info != nil {
		return info, nil
	}
	return nil, fmt.Errorf("响应中未找到有效备案信息")
}

// parseICPJSON 容错解析各备案 API 的 JSON 响应：递归遍历键值，
// 按常见键名匹配出主体/类型/备案号/域名/时间；缺备案号视为无效。
func parseICPJSON(body []byte) *model.ICPInfo {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return nil
	}
	info := &model.ICPInfo{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				s, ok := val.(string)
				if !ok {
					continue
				}
				kl := strings.ToLower(k)
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				switch {
				case info.ICP == "" && (kl == "icp" || kl == "icpno" || kl == "icp_number" || kl == "icpcode" || kl == "beian" || strings.Contains(kl, "icp")):
					if reICPNumber.MatchString(s) {
						info.ICP = s
					}
				case info.Name == "" && (kl == "name" || kl == "unit" || kl == "company" || kl == "company_name" || kl == "unit_name" || kl == "org_name" || kl == "owner" || kl == "entname"):
					if !strings.Contains(s, "成功") && !strings.Contains(s, "失败") {
						info.Name = s
					}
				case info.Type == "" && (kl == "type" || kl == "nature" || kl == "ent_type" || kl == "lic_type"):
					info.Type = s
				case info.Site == "" && (kl == "site" || kl == "domain" || kl == "main_page" || kl == "main_domain" || kl == "web_site" || kl == "homepage"):
					info.Site = s
				case info.Time == "" && (kl == "time" || kl == "update_time" || kl == "create_date" || kl == "audit_time" || kl == "approve_date" || kl == "pass_time"):
					info.Time = s
				}
			}
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(root)
	if info.ICP == "" {
		return nil
	}
	return info
}

// registrableDomain 归一化输入并提取注册域（eTLD+1 的实用近似）。
func registrableDomain(in string) string {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 && !strings.Contains(d, "]") {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	if i := strings.Index(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	d = strings.TrimPrefix(d, "www.")
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return d
	}
	lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if twoLevelTLDs[lastTwo] {
		if len(labels) >= 3 {
			return strings.Join(labels[len(labels)-3:], ".")
		}
		return d
	}
	return lastTwo
}

func hostOf(tpl string) string {
	u, err := url.Parse(tpl)
	if err != nil {
		return tpl
	}
	return u.Host
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "\n... (已截断)"
	}
	return s
}
