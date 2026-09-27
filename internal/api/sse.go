package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gofind/internal/task"
)

// handleTaskEvents GET /api/tasks/{id}/events —— SSE 事件流。
func (s *Server) handleTaskEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, ok := s.mgr.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "任务不存在"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "当前连接不支持流式响应"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsubscribe := s.mgr.Subscribe(id)
	defer unsubscribe()

	send := func(typ string, data any) bool {
		payload, err := json.Marshal(task.Event{TaskID: id, Type: typ, Data: data})
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// 先发当前快照，客户端据此恢复状态
	if !send("snapshot", snap) {
		return
	}
	if isTerminal(snap.Status) {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !send(ev.Type, ev.Data) {
				return
			}
			if ev.Type == "done" {
				return
			}
		}
	}
}

func isTerminal(status string) bool {
	return status == task.StatusDone || status == task.StatusError ||
		status == task.StatusCanceled || status == task.StatusInterrupted
}
