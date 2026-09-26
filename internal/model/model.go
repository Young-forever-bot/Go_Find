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
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"` // brute | crt.sh | hackertarget（多来源逗号合并）
}

// PortResult 端口开放探测结果。
type PortResult struct {
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
	Host    string    `json:"host"`
	IP      string    `json:"ip,omitempty"`
	Port    int       `json:"port"`
	Service string    `json:"service"`
	Version string    `json:"version,omitempty"`
	Banner  string    `json:"banner,omitempty"`
	HTTP    *HTTPInfo `json:"http,omitempty"`
	TLS     *TLSInfo  `json:"tls,omitempty"`
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
