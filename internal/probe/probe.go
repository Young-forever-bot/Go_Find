// Package probe 实现 Web 存活探测与轻量指纹识别：
// 对目标主机尝试 HTTP/HTTPS，记录状态码/标题/Server，并按内置规则库
// 识别常见组件、框架与默认页（ThinkPHP、Shiro、Nacos、宝塔、各类默认页等）。
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"gofind/internal/model"
)

// Options 存活探测参数。
type Options struct {
	Targets []string // 域名或 host:port
	Timeout time.Duration
	Workers int
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// fpRule 指纹规则：在指定位置（body/cookie/header/title）匹配正则。
type fpRule struct {
	Name  string
	Where string // body | cookie | header | title
	Re    *regexp.Regexp
}

func mustFP(name, where, pattern string) fpRule {
	return fpRule{Name: name, Where: where, Re: regexp.MustCompile(pattern)}
}

// fingerprintRules Web 指纹规则库（持续可扩充）。
var fingerprintRules = []fpRule{
	// 开发框架 / 中间件
	mustFP("ThinkPHP", "body", `(?i)thinkphp`),
	mustFP("Shiro", "cookie", `(?i)rememberMe`),
	mustFP("Spring Boot", "body", `Whitelabel Error Page`),
	mustFP("Struts2", "body", `(?i)struts`),
	mustFP("Django", "body", `(?i)csrfmiddlewaretoken`),
	mustFP("Laravel", "cookie", `(?i)laravel_session`),
	mustFP("Flask", "cookie", `(?i)session=.*\.eJw`),
	mustFP("Gin", "header", `(?i)Gin-Gonic`),
	// 中间件 / 管理面
	mustFP("Tomcat", "title", `(?i)Apache Tomcat`),
	mustFP("Jenkins", "header", `(?i)^X-Jenkins`),
	mustFP("Nacos", "body", `(?i)nacos`),
	mustFP("Swagger", "body", `(?i)swagger-ui`),
	mustFP("Druid监控", "body", `(?i)Druid Stat|druid/index`),
	mustFP("phpMyAdmin", "body", `(?i)phpMyAdmin`),
	mustFP("MinIO", "header", `(?i)^MinIO`),
	mustFP("Harbor", "body", `(?i)Harbor`),
	mustFP("Elasticsearch", "body", `(?i)You Know, for Search`),
	mustFP("Kibana", "body", `(?i)kibana`),
	mustFP("GitLab", "body", `(?i)gitlab`),
	mustFP("Gitea", "body", `(?i)Gitea`),
	mustFP("Jira", "body", `(?i)jira`),
	mustFP("Confluence", "body", `(?i)confluence`),
	// CMS
	mustFP("WordPress", "body", `wp-content|wp-includes`),
	mustFP("Typecho", "body", `(?i)typecho`),
	mustFP("Discuz", "body", `(?i)discuz`),
	mustFP("帝国CMS", "body", `(?i)empire\.js|ecms`),
	mustFP("织梦DedeCMS", "body", `(?i)dedecms`),
	// 国内办公/OA 系统
	mustFP("通达OA", "body", `(?i)通达OA|tongda`),
	mustFP("泛微OA", "body", `(?i)泛微|weaver|e-cology`),
	mustFP("用友", "body", `(?i)用友|yonyou|UFIDA`),
	mustFP("金蝶", "body", `(?i)金蝶|kingdee`),
	mustFP("蓝凌OA", "body", `(?i)蓝凌|landray`),
	mustFP("致远OA", "body", `(?i)致远|seeyon`),
	mustFP("禅道", "body", `(?i)禅道|zentao`),
	// 面板
	mustFP("宝塔面板", "body", `(?i)宝塔面板|BT-PANEL|btpanel`),
	// 各类默认页
	mustFP("Nginx默认页", "body", `Welcome to nginx`),
	mustFP("Apache默认页", "body", `Apache2 Default Page|It works!`),
	mustFP("IIS默认页", "title", `IIS Windows Server`),
	mustFP("Tomcat默认页", "body", `(?i)<h1>Apache Tomcat`),
	mustFP("WebLogic默认页", "body", `(?i)Error 404--Not Found`),
}

// Run 执行存活探测，结束返回 nil 或错误。
func Run(ctx context.Context, o Options, emit Emitter) error {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Workers <= 0 {
		o.Workers = 50
	}
	if o.Workers > 500 {
		o.Workers = 500
	}
	var targets []string
	for _, t := range o.Targets {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("目标为空")
	}
	total := len(targets)
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}
	logf("info", "开始存活探测: %d 个目标，超时 %v，并发 %d", total, o.Timeout, o.Workers)

	var done, alive atomic.Int64
	jobs := make(chan string)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for host := range jobs {
			res := probeHost(ctx, host, o.Timeout)
			if res.Alive {
				alive.Add(1)
			}
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
		for _, t := range targets {
			select {
			case <-ctx.Done():
				break outer
			default:
			}
			select {
			case <-ctx.Done():
				break outer
			case jobs <- t:
			}
		}
	}()
	wg.Wait()
	logf("info", "存活探测完成: %d/%d 个目标存活", alive.Load(), total)
	return nil
}

// probeHost 依次尝试 http/https，返回可用性更好的结果。
func probeHost(ctx context.Context, host string, timeout time.Duration) model.ProbeResult {
	res := model.ProbeResult{Host: host}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 候选 URL：带端口的目标只试该端口的两种协议，纯域名先 http 后 https
	var candidates []string
	if strings.Contains(host, ":") {
		candidates = []string{"http://" + host + "/", "https://" + host + "/"}
	} else {
		candidates = []string{"http://" + host + "/", "https://" + host + "/"}
	}

	var best *model.ProbeResult
	for _, u := range candidates {
		info, ok := doProbe(ctx, client, host, u)
		if !ok {
			continue
		}
		if best == nil || better(info, best) {
			best = info
		}
		// 首个 2xx/3xx 即可，不再尝试另一协议
		if info.StatusCode > 0 && info.StatusCode < 400 {
			break
		}
	}
	if best != nil {
		res = *best
		res.Alive = true
	} else {
		res.Error = "无 HTTP 响应"
	}
	return res
}

// better 择优：状态码更低（更正常）的优先。
func better(a, b *model.ProbeResult) bool {
	scoreA, scoreB := statusScore(a.StatusCode), statusScore(b.StatusCode)
	if scoreA != scoreB {
		return scoreA < scoreB
	}
	return strings.HasPrefix(a.URL, "https://") // 同分优先 https
}

func statusScore(code int) int {
	switch {
	case code >= 200 && code < 400:
		return 0
	case code >= 400 && code < 500:
		return 1
	case code >= 500:
		return 2
	default:
		return 3
	}
}

func doProbe(ctx context.Context, client *http.Client, host, u string) (*model.ProbeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 GoFind/1.1")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))

	res := &model.ProbeResult{
		Host:       host,
		URL:        u,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
		Length:     int(resp.ContentLength),
	}
	if res.Length < 0 {
		res.Length = len(body)
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if final := resp.Request.URL.String(); final != u {
			res.URL = final
		}
	}
	res.Title = extractTitle(string(body))

	// 指纹识别
	seen := map[string]struct{}{}
	bodyLower := strings.ToLower(string(body))
	addFP := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		res.Fingerprints = append(res.Fingerprints, name)
	}
	for _, r := range fingerprintRules {
		var hit bool
		switch r.Where {
		case "body":
			hit = r.Re.MatchString(bodyLower)
		case "title":
			hit = r.Re.MatchString(res.Title)
		case "header":
			for k, vs := range resp.Header {
				if r.Re.MatchString(k) {
					hit = true
					break
				}
				for _, v := range vs {
					if r.Re.MatchString(v) {
						hit = true
						break
					}
				}
			}
		case "cookie":
			for _, c := range resp.Cookies() {
				if r.Re.MatchString(c.Name) || r.Re.MatchString(c.Value) {
					hit = true
					break
				}
			}
		}
		if hit {
			addFP(r.Name)
		}
	}
	return res, true
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(m[1])
	t = html.UnescapeString(t)
	t = strings.Join(strings.Fields(t), " ")
	if utf8.RuneCountInString(t) > 200 {
		r := []rune(t)
		t = string(r[:200]) + "..."
	}
	return t
}

// 含端口目标的 host 规范化（保留给上层使用）。
func joinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
