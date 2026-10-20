package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// NativeOptions 是 Go 原生 TCP 扫描参数。
type NativeOptions struct {
	Targets     string `json:"targets"`
	Ports       string `json:"ports"`
	TimeoutMs   int    `json:"timeoutMs"`
	Concurrency int    `json:"concurrency"`
	Discovery   bool   `json:"discovery"`  // 先做 TCP 存活探测，只扫描存活主机
	Banner      bool   `json:"banner"`     // 尝试抓取服务 Banner
	ShowClosed  bool   `json:"showClosed"` // 是否输出关闭的端口
}

// DefaultPorts 是未指定端口时使用的常见端口。
const DefaultPorts = "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"

// 主机存活探测使用的常见端口
var discoveryPorts = []int{80, 443, 22, 445, 3389, 139, 21, 23, 25, 8080}

// Normalize 补齐默认值并限制范围。
func (o *NativeOptions) Normalize() {
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = 800
	}
	if o.TimeoutMs > 10000 {
		o.TimeoutMs = 10000
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 200
	}
	if o.Concurrency > 2000 {
		o.Concurrency = 2000
	}
	if strings.TrimSpace(o.Ports) == "" {
		o.Ports = DefaultPorts
	}
}

type job struct {
	host string
	port int
}

// RunNative 执行原生 TCP connect 扫描，结果通过 emit 实时推送。
func RunNative(ctx context.Context, o NativeOptions, emit Emitter) error {
	o.Normalize()
	hosts, err := ParseTargets(o.Targets)
	if err != nil {
		return err
	}
	ports, err := ParsePorts(o.Ports)
	if err != nil {
		return err
	}
	timeout := time.Duration(o.TimeoutMs) * time.Millisecond
	emit(Event{Type: "log", Message: fmt.Sprintf("原生扫描：%d 个目标，%d 个端口，并发 %d，超时 %v", len(hosts), len(ports), o.Concurrency, timeout)})

	if o.Discovery {
		emit(Event{Type: "log", Message: "正在进行 TCP 存活探测……"})
		hosts = discoverHosts(ctx, hosts, timeout, o.Concurrency)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		emit(Event{Type: "log", Message: fmt.Sprintf("存活主机 %d 个", len(hosts))})
		for _, h := range hosts {
			emit(Event{Type: "host", Host: &HostResult{Address: h, State: "up"}})
		}
	}

	total := len(hosts) * len(ports)
	if total == 0 {
		emit(Event{Type: "progress", Done: 0, Total: 0})
		return nil
	}

	jobs := make(chan job)
	var done int64
	var wg sync.WaitGroup

	workers := o.Concurrency
	if workers > total {
		workers = total
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				state, banner := probe(ctx, j.host, j.port, timeout, o.Banner)
				n := atomic.AddInt64(&done, 1)
				if state == "open" || o.ShowClosed {
					svc := ServiceFromBanner(banner)
					if svc == "" {
						svc = GuessService(j.port)
					}
					emit(Event{Type: "port", Port: &PortResult{
						Host: j.host, Port: j.port, Proto: "tcp", State: state,
						Service: svc, Banner: banner,
					}})
				}
				if n%50 == 0 || int(n) == total {
					emit(Event{Type: "progress", Done: int(n), Total: total})
				}
			}
		}()
	}

feed:
	for _, h := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				break feed
			case jobs <- job{h, p}:
			}
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

// probe 对单个端口做 TCP 连接，返回 open / closed / filtered。
func probe(ctx context.Context, host string, port int, timeout time.Duration, grab bool) (string, string) {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Windows 下拒绝连接的错误码与 Unix 不同，同时按错误文本判断
		if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused") {
			return "closed", ""
		}
		return "filtered", ""
	}
	defer conn.Close()
	if !grab {
		return "open", ""
	}
	return "open", grabBanner(conn, port, timeout)
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	buf := make([]byte, 512)
	// 先被动读取：SSH、FTP、SMTP 等服务会主动发送欢迎信息
	wait := timeout
	if wait > 1500*time.Millisecond {
		wait = 1500 * time.Millisecond
	}
	_ = conn.SetDeadline(time.Now().Add(wait))
	if n, _ := conn.Read(buf); n > 0 {
		return sanitize(string(buf[:n]))
	}
	// 没有主动输出时，发送 HTTP 请求试探（覆盖非标准端口上的 Web 服务）
	_ = conn.SetDeadline(time.Now().Add(timeout + 500*time.Millisecond))
	if _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\nUser-Agent: go-scan-ui\r\n\r\n")); err != nil {
		return ""
	}
	n, _ := conn.Read(buf)
	return sanitize(string(buf[:n]))
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case r >= 32 && r != 0x7f && r != 0xfffd:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 200 {
		out = out[:200] + "…"
	}
	return out
}

// discoverHosts 用 TCP 连接常见端口判断主机是否存活（收到 RST 也视为存活）。
func discoverHosts(ctx context.Context, hosts []string, timeout time.Duration, concurrency int) []string {
	alive := make([]bool, len(hosts))
	idx := make(chan int)
	var wg sync.WaitGroup
	workers := concurrency / 4
	if workers < 1 {
		workers = 1
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				alive[i] = isAlive(ctx, hosts[i], timeout)
			}
		}()
	}
loop:
	for i := range hosts {
		select {
		case <-ctx.Done():
			break loop
		case idx <- i:
		}
	}
	close(idx)
	wg.Wait()
	var out []string
	for i, h := range hosts {
		if alive[i] {
			out = append(out, h)
		}
	}
	return out
}

func isAlive(ctx context.Context, host string, timeout time.Duration) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan bool, len(discoveryPorts))
	for _, p := range discoveryPorts {
		go func(p int) {
			st, _ := probe(ctx, host, p, timeout, false)
			result <- st == "open" || st == "closed"
		}(p)
	}
	for range discoveryPorts {
		if <-result {
			return true
		}
	}
	return false
}

var services = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
	1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// GuessService 根据端口号推测常见服务名。
func GuessService(port int) string { return services[port] }

// ServiceFromBanner 根据 Banner 内容识别常见协议。
func ServiceFromBanner(b string) string {
	l := strings.ToLower(b)
	switch {
	case l == "":
		return ""
	case strings.HasPrefix(l, "http/"):
		return "http"
	case strings.HasPrefix(l, "ssh-"):
		return "ssh"
	case strings.HasPrefix(l, "220") && strings.Contains(l, "ftp"):
		return "ftp"
	case strings.HasPrefix(l, "220") && (strings.Contains(l, "smtp") || strings.Contains(l, "esmtp")):
		return "smtp"
	case strings.HasPrefix(l, "+ok"):
		return "pop3"
	case strings.HasPrefix(l, "* ok"):
		return "imap"
	case strings.Contains(l, "mysql") || strings.Contains(l, "mariadb"):
		return "mysql"
	case strings.HasPrefix(l, "-err") || strings.HasPrefix(l, "-noauth"):
		return "redis"
	case strings.HasPrefix(l, "rfb "):
		return "vnc"
	}
	return ""
}
