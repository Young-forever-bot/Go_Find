// Package pipeline 实现一键全面测绘流水线：
// 子域名收集 → 存活探测(含指纹) → 端口扫描 → 服务识别 → WHOIS/备案，
// 逐阶段编排既有引擎，按阶段打标转发结果事件，并输出汇总。
package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"gofind/internal/model"
	"gofind/internal/portscan"
	"gofind/internal/probe"
	"gofind/internal/service"
	"gofind/internal/subdomain"
	"gofind/internal/whois"
)

// Options 全面测绘参数。
type Options struct {
	Domain      string
	Methods     []string // 子域名收集方式，空则默认全开
	Wordlist    []string
	Concurrency int    // DNS 并发
	DNSServer   string
	TimeoutMs   int    // DNS 超时
	Ports       string // 端口预设/规格，默认 web
	Workers     int    // 端口扫描并发
	DoWhois     bool
	ICPEndpoint string
}

// Emitter 引擎通过它向任务管道发事件。
type Emitter func(model.Event)

var stageNames = []struct{ key, name string }{
	{"subdomain", "子域名收集"},
	{"probe", "存活探测"},
	{"portscan", "端口扫描"},
	{"service", "服务识别"},
	{"whois", "WHOIS/备案"},
}

// collector 捕获各引擎结果用于阶段间传递与汇总，同时打上阶段标记后转发。
type collector struct {
	fwd Emitter
	sub []model.SubdomainResult
	probe []model.ProbeResult
	port []model.PortResult
	svc  []model.ServiceResult
	whoisRes []model.WhoisResult
}

func (c *collector) emit(ev model.Event) {
	switch d := ev.Data.(type) {
	case model.SubdomainResult:
		d.Stage = "subdomain"
		c.sub = append(c.sub, d)
		ev.Data = d
	case model.ProbeResult:
		d.Stage = "probe"
		c.probe = append(c.probe, d)
		ev.Data = d
	case model.PortResult:
		d.Stage = "portscan"
		c.port = append(c.port, d)
		ev.Data = d
	case model.ServiceResult:
		d.Stage = "service"
		c.svc = append(c.svc, d)
		ev.Data = d
	case model.WhoisResult:
		d.Stage = "whois"
		c.whoisRes = append(c.whoisRes, d)
		ev.Data = d
	}
	c.fwd(ev)
}

// Run 执行流水线，结束返回 nil 或错误。
func Run(ctx context.Context, o Options, emit Emitter) error {
	start := time.Now()
	root := strings.ToLower(strings.TrimSpace(o.Domain))
	root = strings.TrimSuffix(root, ".")
	if root == "" || !strings.Contains(root, ".") {
		return fmt.Errorf("无效域名: %q", o.Domain)
	}
	registrable := whois.Registrable(root)
	total := len(stageNames)

	var notes []string
	stage := func(i int, status, note string) {
		emit(model.Event{Type: "stage", Data: model.StageInfo{
			Index: i, Total: total, Key: stageNames[i].key, Name: stageNames[i].name, Status: status, Note: note,
		}})
	}
	logf := func(level, format string, a ...any) {
		emit(model.Event{Type: "log", Data: model.LogEntry{Time: time.Now(), Level: level, Msg: fmt.Sprintf(format, a...)}})
	}

	c := &collector{fwd: emit}

	logf("info", "全面测绘开始: %s (注册域: %s)", root, registrable)

	// ---------- 阶段 1: 子域名收集 ----------
	stage(0, "running", "")
	subOpts := subdomain.Options{
		Domain:      root,
		Methods:     o.Methods,
		Wordlist:    o.Wordlist,
		Concurrency: o.Concurrency,
		DNSServer:   o.DNSServer,
		Timeout:     msDur(o.TimeoutMs),
	}
	err := subdomain.Run(ctx, subOpts, c.emit)
	if err != nil && ctx.Err() == nil {
		stage(0, "fail", err.Error())
		notes = append(notes, "子域名收集失败: "+err.Error())
		logf("warn", "子域名收集失败，将仅以根域名继续: %v", err)
	} else if ctx.Err() != nil {
		stage(0, "fail", "已取消")
		return ctx.Err()
	} else {
		stage(0, "ok", fmt.Sprintf("发现 %d 个子域名", len(c.sub)))
	}

	// 探测目标 = 根域名 + 全部子域名（去重）
	hostSet := map[string]struct{}{root: {}}
	var hosts []string
	for _, s := range c.sub {
		if _, ok := hostSet[s.Subdomain]; !ok {
			hostSet[s.Subdomain] = struct{}{}
			hosts = append(hosts, s.Subdomain)
		}
	}
	hosts = append([]string{root}, hosts...)
	sort.Strings(hosts[1:])

	// ---------- 阶段 2: 存活探测 ----------
	stage(1, "running", fmt.Sprintf("共 %d 个目标", len(hosts)))
	probeErr := probe.Run(ctx, probe.Options{Targets: hosts, Workers: 50}, c.emit)
	var aliveHosts []string
	for _, p := range c.probe {
		if p.Alive {
			aliveHosts = append(aliveHosts, p.Host)
		}
	}
	if probeErr != nil {
		stage(1, "fail", probeErr.Error())
		notes = append(notes, "存活探测失败: "+probeErr.Error())
	} else if ctx.Err() != nil {
		stage(1, "fail", "已取消")
		return ctx.Err()
	} else {
		stage(1, "ok", fmt.Sprintf("%d/%d 存活", len(aliveHosts), len(hosts)))
	}

	// ---------- 阶段 3: 端口扫描 ----------
	ports := strings.TrimSpace(o.Ports)
	if ports == "" {
		ports = "web"
	}
	if len(aliveHosts) == 0 {
		stage(2, "skip", "无存活目标")
		stage(3, "skip", "无存活目标")
		notes = append(notes, "未发现存活 Web 站点，跳过端口扫描与服务识别")
	} else {
		stage(2, "running", fmt.Sprintf("%d 个存活主机", len(aliveHosts)))
		spec := strings.Join(aliveHosts, ",")
		portOpts := portscan.Options{TargetSpec: spec, Ports: ports, Workers: o.Workers}
		err := portscan.Run(ctx, portOpts, c.emit)
		if err != nil && ctx.Err() == nil {
			stage(2, "fail", err.Error())
			notes = append(notes, "端口扫描失败: "+err.Error())
		} else if ctx.Err() != nil {
			stage(2, "fail", "已取消")
			return ctx.Err()
		} else {
			stage(2, "ok", fmt.Sprintf("发现 %d 个开放端口", len(c.port)))
		}

		// ---------- 阶段 4: 服务识别 ----------
		if len(c.port) == 0 {
			stage(3, "skip", "无开放端口")
		} else {
			stage(3, "running", fmt.Sprintf("共 %d 个开放端口", len(c.port)))
			var svcTargets []string
			for _, p := range c.port {
				svcTargets = append(svcTargets, fmt.Sprintf("%s:%d", p.IP, p.Port))
			}
			err := service.Run(ctx, service.Options{Targets: svcTargets, Workers: 50}, c.emit)
			if err != nil && ctx.Err() == nil {
				stage(3, "fail", err.Error())
				notes = append(notes, "服务识别失败: "+err.Error())
			} else if ctx.Err() != nil {
				stage(3, "fail", "已取消")
				return ctx.Err()
			} else {
				stage(3, "ok", fmt.Sprintf("识别 %d 个服务", len(c.svc)))
			}
		}
	}

	// ---------- 阶段 5: WHOIS/备案 ----------
	if o.DoWhois {
		stage(4, "running", registrable)
		whoisOpts := whois.Options{
			Domains:     []string{registrable},
			Timeout:     15 * time.Second,
			DoWhois:     true,
			DoICP:       true,
			ICPEndpoint: o.ICPEndpoint,
		}
		err := whois.Run(ctx, whoisOpts, c.emit)
		if err != nil && ctx.Err() == nil {
			stage(4, "fail", err.Error())
			notes = append(notes, "WHOIS/备案失败: "+err.Error())
		} else if ctx.Err() != nil {
			stage(4, "fail", "已取消")
			return ctx.Err()
		} else {
			stage(4, "ok", "")
		}
	} else {
		stage(4, "skip", "未启用")
	}

	// ---------- 汇总 ----------
	summary := model.PipelineSummary{
		Stage:      "summary",
		Domain:     root,
		Duration:   time.Since(start).Round(time.Second).String(),
		Subdomains: len(c.sub),
		Alive:      len(aliveHosts),
		OpenPorts:  len(c.port),
		Services:   len(c.svc),
		Notes:      notes,
	}
	for _, w := range c.whoisRes {
		summary.Registrar = w.Registrar
		if w.ICP != nil {
			summary.ICP = w.ICP.ICP
		}
	}
	emit(model.Event{Type: "result", Data: summary})
	logf("info", "全面测绘完成: %s，耗时 %s（子域名 %d / 存活 %d / 开放端口 %d / 服务 %d）",
		root, summary.Duration, summary.Subdomains, summary.Alive, summary.OpenPorts, summary.Services)
	return nil
}

func msDur(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}
