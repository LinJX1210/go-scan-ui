package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/LinJX1210/go-scan-ui/internal/scan"
)

const (
	maxEventsPerJob = 200000
	jobRetention    = 30 * time.Minute
)

// Job 表示一次扫描任务，事件会被缓存以便前端断线重连后回放。
type Job struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished,omitempty"`
	Running   bool      `json:"running"`
	cancel    context.CancelFunc
	mu        sync.Mutex
	events    []scan.Event
	notify    chan struct{}
	truncated bool
}

func (j *Job) emit(e scan.Event) {
	j.mu.Lock()
	if len(j.events) < maxEventsPerJob {
		j.events = append(j.events, e)
	} else if !j.truncated {
		j.truncated = true
		j.events = append(j.events, scan.Event{Type: "log", Message: "事件过多，后续输出已截断"})
	}
	close(j.notify)
	j.notify = make(chan struct{})
	j.mu.Unlock()
}

// snapshot 返回从 from 开始的事件、是否仍在运行以及下一次等待用的通道。
func (j *Job) snapshot(from int) ([]scan.Event, bool, <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var evs []scan.Event
	if from < len(j.events) {
		evs = append(evs, j.events[from:]...)
	}
	return evs, j.Running, j.notify
}

// Manager 管理所有扫描任务。
type Manager struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

func NewManager() *Manager {
	m := &Manager{jobs: map[string]*Job{}}
	go m.gc()
	return m
}

// Start 启动一个扫描任务。
func (m *Manager) Start(mode string, run func(ctx context.Context, emit scan.Emitter) error) *Job {
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{ID: newID(), Mode: mode, Started: time.Now(), Running: true, cancel: cancel, notify: make(chan struct{})}
	m.mu.Lock()
	m.jobs[j.ID] = j
	m.mu.Unlock()

	go func() {
		err := run(ctx, j.emit)
		switch {
		case ctx.Err() != nil:
			j.emit(scan.Event{Type: "error", Message: "扫描已停止"})
		case err != nil:
			j.emit(scan.Event{Type: "error", Message: err.Error()})
		}
		j.mu.Lock()
		j.Running = false
		j.Finished = time.Now()
		j.mu.Unlock()
		j.emit(scan.Event{Type: "done", Message: "扫描结束"})
		cancel()
	}()
	return j
}

func (m *Manager) Get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

func (m *Manager) Stop(id string) bool {
	j := m.Get(id)
	if j == nil {
		return false
	}
	j.cancel()
	return true
}

func (m *Manager) gc() {
	for range time.Tick(time.Minute) {
		m.mu.Lock()
		for id, j := range m.jobs {
			j.mu.Lock()
			old := !j.Running && time.Since(j.Finished) > jobRetention
			j.mu.Unlock()
			if old {
				delete(m.jobs, id)
			}
		}
		m.mu.Unlock()
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
