package job

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

type job struct {
	name     string
	interval time.Duration
	fn       func(ctx context.Context) error
}

type Service struct {
	jobs []job
	wg   *sync.WaitGroup
}

func NewService() *Service {
	return &Service{
		wg: &sync.WaitGroup{},
	}
}

func (s *Service) RegisterJob(name string, interval time.Duration, fn func(ctx context.Context) error) *Service {
	return s.TryRegisterJob(true, name, interval, fn)
}

func (s *Service) TryRegisterJob(isEnabled bool, name string, interval time.Duration, fn func(ctx context.Context) error) *Service {
	if !isEnabled {
		return s
	}

	s.jobs = append(s.jobs, job{
		name:     name,
		interval: interval,
		fn:       fn,
	})

	return s
}

func (s *Service) Start(ctx context.Context) {
	for _, v := range s.jobs {
		go s.startJob(ctx, v)
	}
}

func (s *Service) startJob(ctx context.Context, job job) {
	s.wg.Add(1)
	defer s.wg.Done()

	l := slog.Default().With("job", job.name)

	ticker := time.NewTicker(job.interval)
	defer ticker.Stop()

	for {
		l.Debug("job started")

		err := s.withRecover(ctx, l, job)
		if err != nil {
			l.Error("job failed", "error", err)
		} else {
			l.Debug("job done")
		}

		select {
		case <-ctx.Done():
			l.Debug("context done")
			return

		case <-ticker.C:
		}
	}
}

func (s *Service) withRecover(ctx context.Context, l *slog.Logger, j job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			l.Error("job panic", "error", r, "stack", string(debug.Stack()))
		}
	}()

	return j.fn(ctx)
}

func (s *Service) Stop() {
	s.wg.Wait()
}
