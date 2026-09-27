package api

import (
	"context"

	"gofind/internal/model"
	"gofind/internal/pipeline"
	"gofind/internal/portscan"
	"gofind/internal/service"
	"gofind/internal/subdomain"
	"gofind/internal/whois"
)

// emitter 把引擎事件转接进任务管理器。
func (s *Server) emitter(taskID string) func(model.Event) {
	return func(ev model.Event) {
		switch ev.Type {
		case "progress":
			if p, ok := ev.Data.(model.Progress); ok {
				s.mgr.SetProgress(taskID, p.Done, p.Total)
			}
		case "log":
			if l, ok := ev.Data.(model.LogEntry); ok {
				s.mgr.AddLog(taskID, l.Level, l.Msg)
			}
		case "result":
			s.mgr.AddResult(taskID, ev.Data)
		case "stage":
			s.mgr.PublishCustom(taskID, ev.Type, ev.Data)
		}
	}
}

// runSubdomain 子域名任务执行器。
func (s *Server) runSubdomain(id string, opts subdomain.Options) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mgr.SetCancel(id, cancel)
	defer cancel()
	err := subdomain.Run(ctx, opts, s.emitter(id))
	s.mgr.Finish(id, err)
}

// runPortScan 端口扫描任务执行器。
func (s *Server) runPortScan(id string, opts portscan.Options) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mgr.SetCancel(id, cancel)
	defer cancel()
	err := portscan.Run(ctx, opts, s.emitter(id))
	s.mgr.Finish(id, err)
}

// runService 服务识别任务执行器。
func (s *Server) runService(id string, opts service.Options) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mgr.SetCancel(id, cancel)
	defer cancel()
	err := service.Run(ctx, opts, s.emitter(id))
	s.mgr.Finish(id, err)
}

// runWhois WHOIS/备案查询任务执行器。
func (s *Server) runWhois(id string, opts whois.Options) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mgr.SetCancel(id, cancel)
	defer cancel()
	err := whois.Run(ctx, opts, s.emitter(id))
	s.mgr.Finish(id, err)
}

// runPipeline 全面测绘流水线任务执行器。
func (s *Server) runPipeline(id string, opts pipeline.Options) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mgr.SetCancel(id, cancel)
	defer cancel()
	err := pipeline.Run(ctx, opts, s.emitter(id))
	s.mgr.Finish(id, err)
}
