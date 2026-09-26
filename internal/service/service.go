// Package service 实现端口服务识别：Banner 抓取、HTTP/HTTPS 探测、TLS 证书解析、
// 内置指纹匹配与常见端口名兜底。
package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
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

// Options 服务识别参数。
type Options struct {
	Targets []string // host:port 列表
	Timeout time.Duration
	Workers int
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type target struct {
	host string
	port int
}

// Run 执行识别，结束返回 nil 或错误。
func Run(ctx context.Context, o Options, emit Emitter) error {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Workers <= 0 {
		o.Workers = 50
	}
	if o.Workers > 500 {
		o.Workers = 500
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}

	var targets []target
	for _, t := range o.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(t)
		if err != nil {
			return fmt.Errorf("无效目标 %q，需要 host:port 格式", t)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("无效端口: %q", t)
		}
		targets = append(targets, target{host: host, port: port})
	}
	if len(targets) == 0 {
		return fmt.Errorf("目标为空")
	}
	total := len(targets)
	logf("info", "开始服务识别: %d 个目标，超时 %v，并发 %d", total, o.Timeout, o.Workers)

	var done, count atomic.Int64
	jobs := make(chan target)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for t := range jobs {
			res := detectTarget(ctx, t, o.Timeout)
			if res.Service != "unknown" {
				count.Add(1)
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
	logf("info", "服务识别完成: %d/%d 个目标识别出具体服务", count.Load(), total)
	return nil
}

// detectTarget 对单个 host:port 执行探测状态机。
func detectTarget(ctx context.Context, t target, timeout time.Duration) model.ServiceResult {
	res := model.ServiceResult{Host: t.host, Port: t.port, Service: "unknown"}
	if ip := net.ParseIP(t.host); ip != nil {
		res.IP = ip.String()
	} else if ips, err := net.DefaultResolver.LookupHost(ctx, t.host); err == nil && len(ips) > 0 {
		res.IP = ips[0]
	}
	addr := net.JoinHostPort(t.host, strconv.Itoa(t.port))

	banner := sanitizeBanner(grabBanner(ctx, addr, timeout))

	switch {
	case isHTTPish(banner):
		// 对端主动回 HTTP 报文（代理/网关常见），明文 HTTP 概率高
		if hi, ok := probeHTTP(ctx, addr, timeout); ok {
			res.Service = "http"
			res.Banner = banner
			res.HTTP = hi
		} else if hi, ti, ok := probeHTTPS(ctx, addr, t.host, timeout); ok {
			res.Service = "https"
			res.Banner = banner
			res.HTTP = hi
			res.TLS = ti
		}
	case banner != "":
		res.Banner = banner
		name, ver := fingerprint(banner)
		if name != "" {
			res.Service = name
			res.Version = ver
		} else if hi, ti, ok := probeHTTPS(ctx, addr, t.host, timeout); ok && ti != nil {
			// 非空 Banner 且匹配失败，尝试是否为 HTTPS（如某些服务直接 TLS 握手）
			res.Service = "https"
			res.HTTP = hi
			res.TLS = ti
		}
	default:
		// 静默端口：依次尝试 HTTP → HTTPS → 发送探测载荷
		if hi, ok := probeHTTP(ctx, addr, timeout); ok {
			res.Service = "http"
			res.HTTP = hi
		} else if hi, ti, ok := probeHTTPS(ctx, addr, t.host, timeout); ok {
			res.Service = "https"
			res.HTTP = hi
			res.TLS = ti
		} else if b2 := sanitizeBanner(grabWithPayload(ctx, addr, timeout, "\r\n")); b2 != "" {
			res.Banner = b2
			name, ver := fingerprint(b2)
			if name != "" {
				res.Service = name
				res.Version = ver
			}
		}
	}
	if res.Service == "unknown" {
		res.Service = knownPortName(t.port)
	}
	return res
}

// grabBanner 连接后被动读取 Banner。
func grabBanner(ctx context.Context, addr string, timeout time.Duration) []byte {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return buf[:n]
}

// grabWithPayload 连接后发送载荷再读取响应。
func grabWithPayload(ctx context.Context, addr string, timeout time.Duration, payload string) []byte {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return nil
	}
	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return buf[:n]
}

// probeHTTP 明文 HTTP 探测，成功返回 HTTPInfo。
func probeHTTP(ctx context.Context, addr string, timeout time.Duration) (*model.HTTPInfo, bool) {
	client := &http.Client{
		Timeout: timeout + 2*time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	u := "http://" + addr + "/"
	info, ok := doHTTPProbe(ctx, client, u)
	return info, ok
}

// probeHTTPS TLS 握手 + HTTPS 请求探测，返回 HTTPInfo 与 TLSInfo。
// TLS 成功但 HTTP 失败时仍返回 (nil, tlsInfo, true)。
func probeHTTPS(ctx context.Context, addr, host string, timeout time.Duration) (*model.HTTPInfo, *model.TLSInfo, bool) {
	d := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(host) == nil {
		conf.ServerName = host
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, conf)
	if err != nil {
		return nil, nil, false
	}
	defer conn.Close()
	ti := tlsInfoFromConn(conn)

	client := &http.Client{
		Timeout: timeout + 2*time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: conf,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	u := "https://" + addr + "/"
	hi, _ := doHTTPProbe(ctx, client, u)
	return hi, ti, true
}

// doHTTPProbe 发起 GET 并提取状态码/标题/Server/X-Powered-By。
func doHTTPProbe(ctx context.Context, client *http.Client, u string) (*model.HTTPInfo, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "GoFind/1.0")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	info := &model.HTTPInfo{
		StatusCode: resp.StatusCode,
		URL:        u,
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	info.Title = extractTitle(string(body))
	return info, true
}

func tlsInfoFromConn(c *tls.Conn) *model.TLSInfo {
	st := c.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return &model.TLSInfo{}
	}
	cert := st.PeerCertificates[0]
	info := &model.TLSInfo{
		Subject:  cert.Subject.CommonName,
		Issuer:   cert.Issuer.CommonName,
		NotAfter: cert.NotAfter.Format("2006-01-02"),
	}
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	info.SANs = append(info.SANs, cert.DNSNames...)
	return info
}

func isHTTPish(banner string) bool {
	i := strings.Index(banner, "HTTP/")
	return i >= 0 && i < 64
}

func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			sb.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	s := strings.Join(strings.Fields(sb.String()), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
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
