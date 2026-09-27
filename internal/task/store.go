package task

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Store 任务 JSON 文件持久化：整个任务库存为单个 tasks.json，
// 写入采用「临时文件 + 原子重命名」，应用重启后恢复历史任务。
// （相对 SQLite 的取舍：零第三方依赖、体积零增长，桌面单机场景价值一致。）
type Store struct {
	path string
}

// NewStore 初始化存储（自动创建数据目录），失败返回错误。
func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

// Load 读取全部历史任务；文件不存在视为空。
func (s *Store) Load() ([]*Task, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var tasks []*Task
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

// Save 原子写入全部任务。
func (s *Store) Save(tasks []*Task) error {
	data, err := json.Marshal(tasks)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
