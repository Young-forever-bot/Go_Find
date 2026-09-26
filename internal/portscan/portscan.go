// Package portscan 实现 TCP Connect 端口开放探测：目标解析（IP/域名/CIDR）、
// 端口规格解析、goroutine 池并发扫描与进度事件。
package portscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gofind/internal/model"
)

// Options 端口扫描参数。
type Options struct {
	TargetSpec string // 目标列表："1.2.3.4, scanme.org, 10.0.0.0/24"
	Ports      string // 端口规格："common" | "web" | "full" | "80,443,8000-8100"
	Timeout    time.Duration
	Workers    int
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

type targetInfo struct {
	Host string // 用户输入的原始目标（IP/域名/CIDR）
	IP   string // 实际扫描的 IP
}

// Run 执行扫描，结束返回 nil 或错误。
func Run(ctx context.Context, o Options, emit Emitter) error {
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Workers <= 0 {
		o.Workers = 500
	}
	if o.Workers > 5000 {
		o.Workers = 5000
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}

	hosts, err := resolveTargets(ctx, o.TargetSpec, emit)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("没有可扫描的目标")
	}
	ports, err := ParsePorts(o.Ports)
	if err != nil {
		return err
	}
	total := len(hosts) * len(ports)
	if total > 10_000_000 {
		return fmt.Errorf("扫描任务过大: %d 个目标端口", total)
	}

	logf("info", "开始端口扫描: %d 个主机 × %d 个端口，超时 %v，并发 %d", len(hosts), len(ports), o.Timeout, o.Workers)

	type job struct {
		t    targetInfo
		port int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var done, openCount atomic.Int64
	progressStep := total / 200
	if progressStep < 1 {
		progressStep = 1
	}

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			addr := net.JoinHostPort(j.t.IP, strconv.Itoa(j.port))
			d := net.Dialer{Timeout: o.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				openCount.Add(1)
				emit(model.Event{Type: "result", Data: model.PortResult{Host: j.t.Host, IP: j.t.IP, Port: j.port, Status: "open"}})
			}
			n := int(done.Add(1))
			if n%progressStep == 0 || n == total {
				emit(model.Event{Type: "progress", Data: model.Progress{Done: n, Total: total}})
			}
		}
	}
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
	outer:
		for _, t := range hosts {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					break outer
				default:
				}
				select {
				case <-ctx.Done():
					break outer
				case jobs <- job{t, p}:
				}
			}
		}
	}()
	wg.Wait()

	emit(model.Event{Type: "progress", Data: model.Progress{Done: int(done.Load()), Total: total}})
	logf("info", "扫描完成: %d 个开放端口 (已探测 %d/%d)", openCount.Load(), done.Load(), total)
	return nil
}

// resolveTargets 解析混合目标列表为去重后的 host/IP 对。
func resolveTargets(ctx context.Context, spec string, emit Emitter) ([]targetInfo, error) {
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';' || r == '|'
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("目标为空")
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}
	seen := map[string]struct{}{}
	var out []targetInfo
	add := func(host, ip string) {
		key := host + "/" + ip
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, targetInfo{Host: host, IP: ip})
	}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			_, ipnet, err := net.ParseCIDR(f)
			if err != nil {
				return nil, fmt.Errorf("无效 CIDR: %q", f)
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 {
				return nil, fmt.Errorf("仅支持 IPv4 网段: %q", f)
			}
			if bits-ones > 16 {
				return nil, fmt.Errorf("网段过大: %q (最多 /16 展开规模 65536)", f)
			}
			for _, ip := range expandCIDR(ipnet) {
				add(ipnet.String(), ip.String())
			}
			continue
		}
		if ip := net.ParseIP(f); ip != nil {
			add(f, ip.String())
			continue
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(c, f)
		cancel()
		if err != nil || len(addrs) == 0 {
			logf("warn", "域名解析失败，跳过: %s", f)
			continue
		}
		for _, a := range addrs {
			add(f, a)
		}
	}
	return out, nil
}

// expandCIDR 展开一个 IPv4 网段为全部地址（调用方需先保证规模 ≤ 65536）。
func expandCIDR(ipnet *net.IPNet) []net.IP {
	ones, bits := ipnet.Mask.Size()
	size := 1 << (bits - ones)
	start := binary.BigEndian.Uint32(ipnet.IP.To4())
	out := make([]net.IP, 0, size)
	for i := 0; i < size; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start+uint32(i))
		out = append(out, ip)
	}
	return out
}
