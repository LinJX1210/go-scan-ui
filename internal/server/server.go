// Package server 提供 HTTP API 与前端页面。
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/LinJX1210/go-scan-ui/internal/nmap"
	"github.com/LinJX1210/go-scan-ui/internal/scan"
)

// Config 是服务配置。
type Config struct {
	Static fs.FS
	Token  string // 非空时所有 API 需要携带令牌
}

type Server struct {
	cfg  Config
	jobs *Manager
}

func New(cfg Config) http.Handler {
	s := &Server{cfg: cfg, jobs: NewManager()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", s.auth(s.handleInfo))
	mux.HandleFunc("POST /api/nmap/preview", s.auth(s.handlePreview))
	mux.HandleFunc("POST /api/scan", s.auth(s.handleScan))
	mux.HandleFunc("GET /api/scan/{id}/events", s.auth(s.handleEvents))
	mux.HandleFunc("POST /api/scan/{id}/stop", s.auth(s.handleStop))
	mux.HandleFunc("POST /api/tools/preview", s.auth(s.handleToolPreview))
	mux.Handle("GET /", http.FileServerFS(cfg.Static))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got := r.Header.Get("X-Token")
			if got == "" {
				got = r.URL.Query().Get("token") // EventSource 无法设置请求头
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "令牌无效")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"nmap":         nmap.Detect(),
		"root":         os.Geteuid() == 0,
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"tokenEnabled": s.cfg.Token != "",
		"defaultPorts": scan.DefaultPorts,
	})
}

func (s *Server) handleToolPreview(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusForbidden, "此版本仅提供离线演示，不生成或执行外部工具命令")
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	var o nmap.Options
	if err := decode(r, &o); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := nmap.BuildArgs(o)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"command": nmap.CommandString(args), "requiresRoot": o.RequiresRoot()})
}

type scanRequest struct {
	Mode   string             `json:"mode"` // native | nmap | dir | tool
	Native scan.NativeOptions `json:"native"`
	Nmap   nmap.Options       `json:"nmap"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var run func(ctx context.Context, emit scan.Emitter) error
	switch req.Mode {
	case "native":
		o := req.Native
		// 启动前先校验，立即把错误返回给界面
		if _, err := scan.ParseTargets(o.Targets); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if o.Ports != "" {
			if _, err := scan.ParsePorts(o.Ports); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		run = func(ctx context.Context, emit scan.Emitter) error { return scan.RunNative(ctx, o, emit) }
	case "nmap":
		o := req.Nmap
		if _, err := nmap.BuildArgs(o); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		run = func(ctx context.Context, emit scan.Emitter) error { return nmap.Run(ctx, o, emit) }
	case "dir", "tool":
		// 服务端也拒绝执行，不能通过绕过前端恢复真实扫描。
		writeErr(w, http.StatusForbidden, "此模式仅提供浏览器内离线演示，不执行真实扫描")
		return
	default:
		writeErr(w, http.StatusBadRequest, "未知的扫描模式")
		return
	}
	j := s.jobs.Start(req.Mode, run)
	writeJSON(w, map[string]string{"id": j.ID})
}

// handleEvents 以 Server-Sent Events 推送扫描事件。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "不支持流式输出")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	from, _ := strconv.Atoi(r.Header.Get("Last-Event-ID"))
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		evs, running, wait := j.snapshot(from)
		for _, e := range evs {
			b, _ := json.Marshal(e)
			from++
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", from, b)
		}
		flusher.Flush()
		if !running && len(evs) == 0 {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-wait:
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
		}
	}
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if !s.jobs.Stop(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("请求格式错误：%v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
