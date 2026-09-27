// Package task 实现统一的任务管理器：任务创建/状态机/进度与结果存储/事件订阅/取消。
package task

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"gofind/internal/model"
)

// 任务状态。
const (
	StatusRunning    = "running"
	StatusDone       = "done"
	StatusError      = "error"
	StatusCanceled   = "canceled"
	StatusInterrupted = "interrupted" // 应用重启前未完成的任务
)

// Task 一次探测任务的完整状态。
type Task struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"` // subdomain | portscan | service
	Status     string           `json:"status"`
	Params     map[string]any   `json:"params"`
	Progress   model.Progress   `json:"progress"`
	Results    []any            `json:"results"`
	Logs       []model.LogEntry `json:"logs"`
	Error      string           `json:"error,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

// Event 推送给 SSE 订阅者的事件。
type Event struct {
	TaskID string `json:"task_id"`
	Type   string `json:"type"`
	Data   any    `json:"data,omitempty"`
}

// Manager 管理全部生命周期内的任务。
type Manager struct {
	mu      sync.RWMutex
	tasks   map[string]*Task
	cancels map[string]context.CancelFunc
	subs    map[string]map[chan Event]struct{}
	seq     int64
	store   *Store // 可选持久化
}

// NewManager 创建管理器。
func NewManager() *Manager {
	return &Manager{
		tasks:   map[string]*Task{},
		cancels: map[string]context.CancelFunc{},
		subs:    map[string]map[chan Event]struct{}{},
	}
}

// NewManagerWithStore 创建带持久化的管理器：从存储恢复历史任务
// （恢复时 running 状态标记为 interrupted），任务收尾/删除时自动落盘。
func NewManagerWithStore(store *Store) *Manager {
	m := NewManager()
	m.store = store
	tasks, err := store.Load()
	if err != nil {
		return m
	}
	for _, t := range tasks {
		if t.Status == StatusRunning {
			t.Status = StatusInterrupted
		}
		if t.Results == nil {
			t.Results = []any{}
		}
		if t.Logs == nil {
			t.Logs = []model.LogEntry{}
		}
		m.tasks[t.ID] = t
	}
	return m
}

// persist 异步落盘全部任务快照。
func (m *Manager) persist() {
	if m.store == nil {
		return
	}
	m.mu.RLock()
	out := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		cp := m.snapshot(t)
		out = append(out, &cp)
	}
	m.mu.RUnlock()
	tasks := out
	go func() { _ = m.store.Save(tasks) }()
}

// Create 新建任务并置为 running。
func (m *Manager) Create(typ string, params map[string]any) *Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	t := &Task{
		ID:        fmt.Sprintf("%d-%d", time.Now().UnixMilli(), m.seq),
		Type:      typ,
		Status:    StatusRunning,
		Params:    params,
		Results:   []any{},
		Logs:      []model.LogEntry{},
		CreatedAt: time.Now(),
	}
	m.tasks[t.ID] = t
	return t
}

// Get 返回任务快照（切片做定长拷贝，避免与并发 append 产生数据竞争）。
func (m *Manager) Get(id string) (Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	if !ok {
		return Task{}, false
	}
	return m.snapshot(t), true
}

// List 返回全部任务快照，按创建时间倒序。
func (m *Manager) List() []Task {
	m.mu.RLock()
	out := make([]Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		out = append(out, m.snapshot(t))
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Delete 取消运行中的任务并从内存移除。
func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	_, ok := m.tasks[id]
	if ok {
		if c, ok := m.cancels[id]; ok {
			c()
		}
		delete(m.tasks, id)
		delete(m.cancels, id)
		delete(m.subs, id)
	}
	m.mu.Unlock()
	if ok {
		m.persist()
	}
	return ok
}

// SetCancel 登记任务的取消函数。
func (m *Manager) SetCancel(id string, cancel context.CancelFunc) {
	m.mu.Lock()
	m.cancels[id] = cancel
	m.mu.Unlock()
}

// Cancel 取消任务（调用其 cancel 函数），不修改状态——状态由 runner 的 Finish 收尾。
func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	_, ok := m.tasks[id]
	c, hasCancel := m.cancels[id]
	m.mu.Unlock()
	if ok && hasCancel {
		c()
	}
	return ok
}

// SetProgress 设置进度。
func (m *Manager) SetProgress(id string, done, total int) {
	m.mu.Lock()
	t := m.tasks[id]
	if t != nil {
		t.Progress = model.Progress{Done: done, Total: total}
	}
	m.mu.Unlock()
	if t != nil {
		m.publish(id, "progress", model.Progress{Done: done, Total: total})
	}
}

// AddResult 追加一条结果。
func (m *Manager) AddResult(id string, v any) {
	m.mu.Lock()
	t := m.tasks[id]
	if t != nil {
		t.Results = append(t.Results, v)
	}
	m.mu.Unlock()
	if t != nil {
		m.publish(id, "result", v)
	}
}

// AddLog 追加一条日志。
func (m *Manager) AddLog(id string, level, msg string) {
	entry := model.LogEntry{Time: time.Now(), Level: level, Msg: msg}
	m.mu.Lock()
	t := m.tasks[id]
	if t != nil {
		t.Logs = append(t.Logs, entry)
	}
	m.mu.Unlock()
	if t != nil {
		m.publish(id, "log", entry)
	}
}

// Finish 任务收尾：err 为 nil → done；context.Canceled → canceled；其余 → error。
func (m *Manager) Finish(id string, err error) {
	status, errMsg := StatusDone, ""
	if err != nil {
		if errors.Is(err, context.Canceled) {
			status = StatusCanceled
		} else {
			status = StatusError
			errMsg = err.Error()
		}
	}
	now := time.Now()
	m.mu.Lock()
	t := m.tasks[id]
	if t != nil {
		t.Status = status
		t.Error = errMsg
		t.FinishedAt = &now
	}
	delete(m.cancels, id)
	m.mu.Unlock()
	if t != nil {
		m.publish(id, "done", map[string]any{"status": status, "error": errMsg})
		m.persist()
	}
}

// PublishCustom 发布无状态事件（如流水线 stage）给该任务的全部订阅者。
func (m *Manager) PublishCustom(id, typ string, data any) {
	m.publish(id, typ, data)
}

// Subscribe 注册一个 SSE 订阅通道，返回退订函数。
func (m *Manager) Subscribe(id string) (<-chan Event, func()) {	ch := make(chan Event, 1024)
	m.mu.Lock()
	if _, ok := m.subs[id]; !ok {
		m.subs[id] = map[chan Event]struct{}{}
	}
	m.subs[id][ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		if set, ok := m.subs[id]; ok {
			delete(set, ch)
		}
		m.mu.Unlock()
	}
}

// publish 向该任务的全部订阅者非阻塞投递事件（慢消费者丢事件而不拖垮扫描）。
func (m *Manager) publish(id, typ string, data any) {
	m.mu.RLock()
	chans := make([]chan Event, 0, len(m.subs[id]))
	for ch := range m.subs[id] {
		chans = append(chans, ch)
	}
	m.mu.RUnlock()
	for _, ch := range chans {
		select {
		case ch <- Event{TaskID: id, Type: typ, Data: data}:
		default:
		}
	}
}

// snapshot 定长拷贝切片后返回任务副本。
func (m *Manager) snapshot(t *Task) Task {
	cp := *t
	cp.Results = make([]any, len(t.Results))
	copy(cp.Results, t.Results)
	cp.Logs = make([]model.LogEntry, len(t.Logs))
	copy(cp.Logs, t.Logs)
	if t.Params != nil {
		p := make(map[string]any, len(t.Params))
		for k, v := range t.Params {
			p[k] = v
		}
		cp.Params = p
	}
	return cp
}
