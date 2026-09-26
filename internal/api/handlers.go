package api

import (
	"net/http"
	"strings"

	"gofind/internal/portscan"
	"gofind/internal/service"
	"gofind/internal/subdomain"
	"gofind/internal/task"
	"gofind/internal/whois"
)

// handleTaskList GET /api/tasks
func (s *Server) handleTaskList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.List())
}

// handleTaskGet GET /api/tasks/{id}
func (s *Server) handleTaskGet(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "任务不存在"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleTaskDelete DELETE /api/tasks/{id} —— 取消运行中任务或删除历史任务。
func (s *Server) handleTaskDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if t, ok := s.mgr.Get(id); ok && t.Status == task.StatusRunning {
		s.mgr.Cancel(id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "canceled"})
		return
	}
	if s.mgr.Delete(id) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": "deleted"})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "任务不存在"})
}

// handleSubdomain POST /api/subdomain
func (s *Server) handleSubdomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain      string   `json:"domain"`
		Methods     []string `json:"methods"`
		Wordlist    []string `json:"wordlist"`
		Concurrency int      `json:"concurrency"`
		DNSServer   string   `json:"dns"`
		TimeoutMs   int      `json:"timeout_ms"`
	}
	if !bindJSON(w, r, &req) {
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !strings.Contains(domain, ".") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "需要提供有效域名，例如 example.com"})
		return
	}
	opts := subdomain.Options{
		Domain:      domain,
		Methods:     req.Methods,
		Wordlist:    req.Wordlist,
		Concurrency: req.Concurrency,
		DNSServer:   strings.TrimSpace(req.DNSServer),
		Timeout:     msDur(req.TimeoutMs),
	}
	params := map[string]any{
		"domain":       domain,
		"methods":      req.Methods,
		"concurrency":  req.Concurrency,
		"dns":          req.DNSServer,
		"timeout_ms":   req.TimeoutMs,
		"wordlist_len": len(req.Wordlist),
	}
	t := s.mgr.Create("subdomain", params)
	go s.runSubdomain(t.ID, opts)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID})
}

// handlePortScan POST /api/portscan
func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets   string `json:"targets"`
		Ports     string `json:"ports"`
		TimeoutMs int    `json:"timeout_ms"`
		Workers   int    `json:"workers"`
	}
	if !bindJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Targets) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "需要提供扫描目标"})
		return
	}
	opts := portscan.Options{
		TargetSpec: req.Targets,
		Ports:      req.Ports,
		Timeout:    msDur(req.TimeoutMs),
		Workers:    req.Workers,
	}
	params := map[string]any{
		"targets":    req.Targets,
		"ports":      req.Ports,
		"timeout_ms": req.TimeoutMs,
		"workers":    req.Workers,
	}
	t := s.mgr.Create("portscan", params)
	go s.runPortScan(t.ID, opts)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID})
}

// handleService POST /api/service
func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets   []string `json:"targets"`
		TimeoutMs int      `json:"timeout_ms"`
		Workers   int      `json:"workers"`
	}
	if !bindJSON(w, r, &req) {
		return
	}
	if len(req.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "需要提供 host:port 目标列表"})
		return
	}
	opts := service.Options{
		Targets: req.Targets,
		Timeout: msDur(req.TimeoutMs),
		Workers: req.Workers,
	}
	params := map[string]any{
		"targets":    req.Targets,
		"timeout_ms": req.TimeoutMs,
		"workers":    req.Workers,
	}
	t := s.mgr.Create("service", params)
	go s.runService(t.ID, opts)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID})
}

// handleWhois POST /api/whois
func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains     []string `json:"domains"`
		Whois       *bool    `json:"whois"` // 缺省 true
		ICP         *bool    `json:"icp"`   // 缺省 true
		TimeoutMs   int      `json:"timeout_ms"`
		Workers     int      `json:"workers"`
		ICPEndpoint string   `json:"icp_api"`
	}
	if !bindJSON(w, r, &req) {
		return
	}
	var domains []string
	for _, d := range req.Domains {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "需要提供域名列表"})
		return
	}
	opts := whois.Options{
		Domains:     domains,
		Timeout:     msDur(req.TimeoutMs),
		DoWhois:     req.Whois == nil || *req.Whois,
		DoICP:       req.ICP == nil || *req.ICP,
		Workers:     req.Workers,
		ICPEndpoint: strings.TrimSpace(req.ICPEndpoint),
	}
	params := map[string]any{
		"domains":    domains,
		"whois":      opts.DoWhois,
		"icp":        opts.DoICP,
		"timeout_ms": req.TimeoutMs,
		"workers":    req.Workers,
		"icp_api":    req.ICPEndpoint,
	}
	t := s.mgr.Create("whois", params)
	go s.runWhois(t.ID, opts)
	writeJSON(w, http.StatusOK, map[string]any{"task_id": t.ID})
}
