// Package model 定义跨模块共享的数据结构：结果、事件、进度与日志。
package model

import "time"

// Progress 任务进度。
type Progress struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// LogEntry 任务日志条目。
type LogEntry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // info | warn | error
	Msg   string    `json:"msg"`
}

// Event 引擎向任务管理器发出的事件。
type Event struct {
	Type string `json:"type"` // progress | log | result | done
	Data any    `json:"data,omitempty"`
}

// SubdomainResult 子域名收集结果。
type SubdomainResult struct {
	Stage     string   `json:"stage,omitempty"` // 流水线中所属阶段
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"` // brute | crt.sh | hackertarget（多来源逗号合并）
}

// PortResult 端口开放探测结果。
type PortResult struct {
	Stage  string `json:"stage,omitempty"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Status string `json:"status"` // open
}

// HTTPInfo HTTP 探测信息。
type HTTPInfo struct {
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
	PoweredBy  string `json:"powered_by,omitempty"`
	URL        string `json:"url"`
}

// TLSInfo TLS 证书信息。
type TLSInfo struct {
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	SANs     []string `json:"sans,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
}

// ServiceResult 服务识别结果。
type ServiceResult struct {
	Stage   string    `json:"stage,omitempty"`
	Host    string    `json:"host"`
	IP      string    `json:"ip,omitempty"`
	Port    int       `json:"port"`
	Service string    `json:"service"`
	Version string    `json:"version,omitempty"`
	Banner  string    `json:"banner,omitempty"`
	HTTP    *HTTPInfo `json:"http,omitempty"`
	TLS     *TLSInfo  `json:"tls,omitempty"`
}

// ProbeResult Web 存活探测结果。
type ProbeResult struct {
	Stage        string   `json:"stage,omitempty"`
	Host         string   `json:"host"`
	URL          string   `json:"url"`      // 实际可访问的 URL（http/https 择优）
	Alive        bool     `json:"alive"`    // 是否有 HTTP 响应
	StatusCode   int      `json:"status_code,omitempty"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	PoweredBy    string   `json:"powered_by,omitempty"`
	Length       int      `json:"length,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"` // Web 指纹（组件/框架/默认页）
	Error        string   `json:"error,omitempty"`
}

// StageInfo 流水线阶段状态。
type StageInfo struct {
	Index int    `json:"index"` // 从 0 开始
	Total int    `json:"total"`
	Key   string `json:"key"`   // 阶段标识
	Name  string `json:"name"`
	Status string `json:"status"` // pending | running | ok | fail | skip
	Note  string `json:"note,omitempty"`
}

// PipelineSummary 全面测绘汇总。
type PipelineSummary struct {
	Stage      string   `json:"stage,omitempty"`
	Domain     string   `json:"domain"`
	Duration   string   `json:"duration"`
	Subdomains int      `json:"subdomains"`
	Alive      int      `json:"alive"`
	OpenPorts  int      `json:"open_ports"`
	Services   int      `json:"services"`
	Registrar  string   `json:"registrar,omitempty"`
	ICP        string   `json:"icp,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// ICPInfo ICP 备案信息。
type ICPInfo struct {
	Name string `json:"name"` // 备案主体
	Type string `json:"type"` // 企业/个人等
	ICP  string `json:"icp"`  // 备案号
	Site string `json:"site"` // 网站域名
	Time string `json:"time"` // 审核时间
}

// WhoisResult WHOIS 与 ICP 备案查询结果。
type WhoisResult struct {
	Stage        string   `json:"stage,omitempty"`
	Domain       string   `json:"domain"`      // 用户输入的域名
	Registrable  string   `json:"registrable"` // 归一化后的注册域（eTLD+1）
	Registrar    string   `json:"registrar,omitempty"`
	CreationDate string   `json:"creation_date,omitempty"`
	ExpiryDate   string   `json:"expiry_date,omitempty"`
	Status       string   `json:"status,omitempty"`
	NameServers  []string `json:"name_servers,omitempty"`
	Raw          string   `json:"raw,omitempty"` // 原始 WHOIS 输出（截断）
	ICP          *ICPInfo `json:"icp,omitempty"`
	WhoisError   string   `json:"whois_error,omitempty"`
	ICPError     string   `json:"icp_error,omitempty"`
}
