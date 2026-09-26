// Package api 提供 HTTP API：路由、CORS、REST 处理器、SSE 事件流与结果导出。
package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"gofind/internal/task"
)

// Server HTTP 服务。
type Server struct {
	mgr     *task.Manager
	version string
	webDir  string // 前端静态目录，非空时托管 Web 控制台
}

// NewServer 创建服务。
func NewServer(mgr *task.Manager, version, webDir string) *Server {
	return &Server{mgr: mgr, version: version, webDir: webDir}
}

// Handler 构建路由与中间件。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/subdomain", s.handleSubdomain)
	mux.HandleFunc("POST /api/portscan", s.handlePortScan)
	mux.HandleFunc("POST /api/service", s.handleService)
	mux.HandleFunc("POST /api/whois", s.handleWhois)
	mux.HandleFunc("GET /api/tasks", s.handleTaskList)
	mux.HandleFunc("GET /api/tasks/{id}", s.handleTaskGet)
	mux.HandleFunc("DELETE /api/tasks/{id}", s.handleTaskDelete)
	mux.HandleFunc("GET /api/tasks/{id}/events", s.handleTaskEvents)
	mux.HandleFunc("GET /api/tasks/{id}/export", s.handleTaskExport)
	if s.webDir != "" {
		abs, err := filepath.Abs(s.webDir)
		if err == nil {
			s.webDir = abs
			mux.Handle("GET /", http.FileServer(http.Dir(s.webDir)))
		}
	}
	return cors(mux)
}

// cors 允许 Electron file:// 源（Origin: null）及任意本地调试来源访问。
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func bindJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON: " + err.Error()})
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

// msDur 将毫秒数转为 Duration，非正数返回 0。
func msDur(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}
