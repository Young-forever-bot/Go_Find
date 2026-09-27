package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gofind/internal/task"
)

// csvColumns 各任务类型的 CSV 列（支持 "http.title" 形式的嵌套取值）。
var csvColumns = map[string][]string{
	"subdomain": {"subdomain", "ips", "source"},
	"portscan":  {"host", "ip", "port", "status"},
	"service":   {"host", "ip", "port", "service", "version", "banner",
		"http.status_code", "http.title", "http.server", "http.url", "tls.subject", "tls.issuer"},
	"whois": {"domain", "registrable", "registrar", "creation_date", "expiry_date", "status",
		"name_servers", "icp.name", "icp.type", "icp.icp", "icp.site", "icp.time",
		"whois_error", "icp_error"},
	"pipeline": {"stage", "subdomain", "ips", "host", "url", "alive", "status_code", "title",
		"fingerprints", "ip", "port", "status", "service", "version", "banner",
		"domain", "registrar", "icp", "subdomains", "open_ports", "duration"},
}

// handleTaskExport GET /api/tasks/{id}/export?format=csv|json
func (s *Server) handleTaskExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.mgr.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "任务不存在"})
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	switch format {
	case "csv":
		data := buildCSV(t)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="gofind_%s.csv"`, sanitizeFilename(t.ID)))
		_, _ = w.Write(data)
	case "json", "":
		data, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="gofind_%s.json"`, sanitizeFilename(t.ID)))
		_, _ = w.Write(data)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format 仅支持 csv 或 json"})
	}
}

// buildCSV 生成带 UTF-8 BOM 的 CSV（Excel 直接打开不乱码）。
func buildCSV(t task.Task) []byte {
	cols, ok := csvColumns[t.Type]
	if !ok {
		cols = []string{"json"}
	}
	var sb strings.Builder
	sb.WriteString("\uFEFF")
	for i, c := range cols {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(csvEscape(c))
	}
	sb.WriteByte('\n')
	for _, raw := range t.Results {
		m := resultToMap(raw)
		for i, c := range cols {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(csvEscape(fmt.Sprintf("%v", csvLookup(m, c))))
		}
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// resultToMap 把结果结构体统一转为 map（经 JSON 往返，忽略错误）。
func resultToMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return map[string]any{}
	}
	return m
}

// csvLookup 支持 "http.title" 点号路径取值；切片值序列化为分号分隔。
func csvLookup(m map[string]any, path string) any {
	cur := any(m)
	for _, key := range strings.Split(path, ".") {
		cm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = cm[key]
		if !ok {
			return ""
		}
	}
	return cur
}

func csvEscape(s string) string {
	if s == "nil" {
		s = ""
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		s = "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func sanitizeFilename(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}
