// go-scan-ui：IP/端口扫描可视化工具。
//
// 仅可用于你拥有或已获得书面授权的网络与系统。
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/LinJX1210/go-scan-ui/internal/nmap"
	"github.com/LinJX1210/go-scan-ui/internal/server"
	"github.com/LinJX1210/go-scan-ui/web"
)

var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "监听地址（默认只允许本机访问）")
	token := flag.String("token", os.Getenv("GOSCAN_TOKEN"), "访问令牌；监听非本机地址时强烈建议设置（也可用环境变量 GOSCAN_TOKEN）")
	showVer := flag.Bool("version", false, "显示版本")
	flag.Parse()

	if *showVer {
		fmt.Println("go-scan-ui", version)
		return
	}

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("监听地址无效：%v", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		if *token == "" {
			log.Fatalf("监听 %s 会让其他机器使用本扫描器，必须通过 -token 设置访问令牌", *addr)
		}
		log.Printf("⚠ 正在监听非本机地址 %s，已启用访问令牌", *addr)
	}

	info := nmap.Detect()
	if info.Available {
		log.Printf("检测到 nmap：%s", info.Version)
	} else {
		log.Printf("未检测到 nmap，仅可使用原生扫描模式（Kali：sudo apt install nmap）")
	}
	if os.Geteuid() != 0 {
		log.Printf("提示：未以 root 运行，nmap 的 SYN/UDP/OS 探测等功能需要 sudo")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(server.Config{Static: web.Static(), Token: *token}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("go-scan-ui %s 已启动：http://%s", version, *addr)
	log.Printf("仅可扫描你拥有或已获授权的目标")
	log.Fatal(srv.ListenAndServe())
}
