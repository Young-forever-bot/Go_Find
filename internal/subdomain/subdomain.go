// Package subdomain 实现子域名收集：DNS 字典爆破、crt.sh 证书透明度、HackerTarget，
// 带泛解析检测过滤与多来源合并。
package subdomain

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gofind/internal/model"
)

//go:embed data/subdomains.txt
var builtinWordlist string

// Options 子域名收集参数。
type Options struct {
	Domain      string
	Methods     []string // brute | crtsh | hackertarget
	Wordlist    []string // 自定义字典，为空时使用内置字典
	Concurrency int      // DNS 并发数
	DNSServer   string   // 自定义 DNS 服务器（如 223.5.5.5），为空用系统解析
	Timeout     time.Duration
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

var httpClient = &http.Client{}

// Run 执行收集流程，结束后返回 nil 或错误（ctx 取消返回 ctx.Err()）。
func Run(ctx context.Context, o Options, emit Emitter) error {
	domain := strings.ToLower(strings.TrimSpace(o.Domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return fmt.Errorf("无效域名: %q", o.Domain)
	}
	if len(o.Methods) == 0 {
		o.Methods = []string{"brute", "crtsh", "hackertarget"}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	validMethods := map[string]bool{"brute": true, "crtsh": true, "hackertarget": true}
	enabled := map[string]bool{}
	for _, m := range o.Methods {
		if !validMethods[m] {
			return fmt.Errorf("无效的收集方式: %q", m)
		}
		enabled[m] = true
	}

	resolver := newResolver(o.DNSServer, o.Timeout)

	var done, total atomic.Int64
	addDone := func() {
		emit(model.Event{Type: "progress", Data: model.Progress{Done: int(done.Add(1)), Total: int(total.Load())}})
	}
	setTotal := func(n int64) {
		total.Store(n)
		emit(model.Event{Type: "progress", Data: model.Progress{Done: int(done.Load()), Total: int(total.Load())}})
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}

	logf("info", "开始收集子域名: %s (方式: %s)", domain, strings.Join(o.Methods, ", "))

	// 1. 泛解析检测
	wildIPs := detectWildcard(ctx, resolver, domain, o.Timeout)
	if len(wildIPs) > 0 {
		logf("warn", "检测到泛解析 (%d 个 IP)，将过滤完全命中泛解析 IP 的结果", len(wildIPs))
	}

	type entry struct {
		ips     []string
		sources map[string]struct{}
	}
	var (
		mu      sync.Mutex
		entries = map[string]*entry{}
	)
	add := func(sub, source string, ips []string) {
		sub = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sub), "."))
		if sub == "" || !strings.HasSuffix(sub, "."+domain) {
			return
		}
		if isWildcardIPs(ips, wildIPs) {
			return
		}
		mu.Lock()
		e := entries[sub]
		if e == nil {
			e = &entry{sources: map[string]struct{}{}}
			entries[sub] = e
		}
		e.sources[source] = struct{}{}
		if len(ips) > 0 && len(e.ips) == 0 {
			e.ips = ips
		}
		mu.Unlock()
	}

	// 2. 被动收集（crt.sh / HackerTarget）
	passiveCount := int64(0)
	if enabled["crtsh"] {
		passiveCount++
	}
	if enabled["hackertarget"] {
		passiveCount++
	}

	// 3. 字典爆破
	var brute []string
	if enabled["brute"] {
		if len(o.Wordlist) > 0 {
			brute = dedupe(o.Wordlist)
		} else {
			for _, line := range strings.Split(builtinWordlist, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					brute = append(brute, line)
				}
			}
		}
	}
	setTotal(passiveCount + int64(len(brute)))

	if enabled["crtsh"] {
		logf("info", "[crt.sh] 查询证书透明度日志 ...")
		subs, err := fetchCrtSh(ctx, domain)
		if err != nil {
			logf("warn", "[crt.sh] 查询失败: %v", err)
		} else {
			for sub := range subs {
				add(sub, "crt.sh", nil)
			}
			logf("info", "[crt.sh] 获取到 %d 条候选记录", len(subs))
		}
		addDone()
	}

	if enabled["hackertarget"] {
		logf("info", "[hackertarget] 查询主机记录 ...")
		hosts, err := fetchHackerTarget(ctx, domain)
		if err != nil {
			logf("warn", "[hackertarget] 查询失败: %v", err)
		} else {
			for sub, ips := range hosts {
				add(sub, "hackertarget", ips)
			}
			logf("info", "[hackertarget] 获取到 %d 条记录", len(hosts))
		}
		addDone()
	}

	if enabled["brute"] && len(brute) > 0 {
		logf("info", "[爆破] 使用 %d 条字典记录，并发 %d", len(brute), o.Concurrency)
		var wg sync.WaitGroup
		sem := make(chan struct{}, o.Concurrency)
		for _, w := range brute {
			select {
			case <-ctx.Done():
			case sem <- struct{}{}:
			}
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(prefix string) {
				defer wg.Done()
				defer func() { <-sem }()
				host := prefix + "." + domain
				ips, err := lookupHost(ctx, resolver, host, o.Timeout)
				if err == nil && len(ips) > 0 && !isWildcardIPs(ips, wildIPs) {
					add(host, "brute", ips)
				}
				addDone()
			}(w)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// 4. 为被动收集到但尚无 IP 的子域补一次解析
	mu.Lock()
	var needResolve []string
	for sub, e := range entries {
		if len(e.ips) == 0 {
			needResolve = append(needResolve, sub)
		}
	}
	mu.Unlock()
	if len(needResolve) > 0 {
		total.Add(int64(len(needResolve)))
		logf("info", "解析 %d 个被动收集子域名的 IP ...", len(needResolve))
		var wg sync.WaitGroup
		sem := make(chan struct{}, o.Concurrency)
		for _, sub := range needResolve {
			select {
			case <-ctx.Done():
			case sem <- struct{}{}:
			}
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				defer func() { <-sem }()
				ips, err := lookupHost(ctx, resolver, sub, o.Timeout)
				mu.Lock()
				defer mu.Unlock()
				e := entries[sub]
				if e == nil {
					return
				}
				if err != nil || len(ips) == 0 || isWildcardIPs(ips, wildIPs) {
					delete(entries, sub)
					return
				}
				e.ips = ips
				addDone()
			}(sub)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// 5. 输出结果
	mu.Lock()
	results := make([]model.SubdomainResult, 0, len(entries))
	for sub, e := range entries {
		srcs := make([]string, 0, len(e.sources))
		for s := range e.sources {
			srcs = append(srcs, s)
		}
		sortStrings(srcs)
		results = append(results, model.SubdomainResult{Subdomain: sub, IPs: e.ips, Source: strings.Join(srcs, ",")})
	}
	mu.Unlock()
	sortStringsBy(results, func(i, j model.SubdomainResult) bool { return i.Subdomain < j.Subdomain })
	for _, r := range results {
		emit(model.Event{Type: "result", Data: r})
	}
	logf("info", "子域名收集完成，共 %d 条", len(results))
	return nil
}

// detectWildcard 用随机前缀探测泛解析，返回泛解析 IP 集合（nil 表示无泛解析）。
func detectWildcard(ctx context.Context, r *net.Resolver, domain string, timeout time.Duration) map[string]struct{} {
	set := map[string]struct{}{}
	found := false
	for i := 0; i < 3 && !found; i++ {
		host := randLabel(10) + "." + domain
		ips, err := lookupHost(ctx, r, host, timeout)
		if err == nil && len(ips) > 0 {
			found = true
			for _, ip := range ips {
				set[ip] = struct{}{}
			}
		}
	}
	if !found {
		return nil
	}
	return set
}

// isWildcardIPs 判断结果 IP 是否全部命中泛解析 IP。
func isWildcardIPs(ips []string, wild map[string]struct{}) bool {
	if len(wild) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if _, ok := wild[ip]; !ok {
			return false
		}
	}
	return true
}

func newResolver(dnsServer string, timeout time.Duration) *net.Resolver {
	if dnsServer == "" {
		return net.DefaultResolver
	}
	addr := dnsServer
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func lookupHost(ctx context.Context, r *net.Resolver, host string, timeout time.Duration) ([]string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.LookupHost(c, host)
}

func fetchCrtSh(ctx context.Context, domain string) (map[string]struct{}, error) {
	c, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	u := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	req, err := http.NewRequestWithContext(c, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoFind/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var list []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	set := map[string]struct{}{}
	for _, it := range list {
		for _, name := range strings.Split(it.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" {
				set[name] = struct{}{}
			}
		}
	}
	return set, nil
}

func fetchHackerTarget(ctx context.Context, domain string) (map[string][]string, error) {
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(c, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoFind/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	text := string(body)
	if strings.Contains(text, "API count exceeded") {
		return nil, fmt.Errorf("API 配额已超限")
	}
	out := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ",") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		sub := strings.ToLower(strings.TrimSpace(parts[0]))
		var ips []string
		for _, ip := range strings.Fields(strings.TrimSpace(parts[1])) {
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
		if sub != "" && len(ips) > 0 {
			out[sub] = ips
		}
	}
	return out, nil
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func sortStringsBy[T any](s []T, less func(a, b T) bool) {
	sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
}

const letters = "abcdefghijklmnopqrstuvwxyz0123456789"

func randLabel(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
