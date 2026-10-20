package nmap

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/LinJX1210/go-scan-ui/internal/scan"
)

// Info 描述本机 nmap 的可用情况。
type Info struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
}

// Detect 检查 PATH 中是否有 nmap。
func Detect() Info {
	p, err := exec.LookPath("nmap")
	if err != nil {
		return Info{}
	}
	info := Info{Available: true, Path: p}
	out, err := exec.Command(p, "--version").Output()
	if err == nil {
		line := strings.SplitN(string(out), "\n", 2)[0]
		info.Version = strings.TrimSpace(line)
	}
	return info
}

var progressRe = regexp.MustCompile(`About ([0-9.]+)% done`)

// Run 执行 nmap，实时转发输出，结束后解析 XML 并推送结构化结果。
func Run(ctx context.Context, o Options, emit scan.Emitter) error {
	info := Detect()
	if !info.Available {
		return fmt.Errorf("未找到 nmap，请先安装（Kali：sudo apt install nmap）")
	}
	args, err := BuildArgs(o)
	if err != nil {
		return err
	}
	if o.RequiresRoot() && os.Geteuid() != 0 {
		emit(scan.Event{Type: "log", Message: "⚠ 当前选项需要 root 权限，若扫描失败请用 sudo 运行本程序"})
	}

	tmp, err := os.CreateTemp("", "go-scan-ui-*.xml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	full := append([]string{"-oX", tmpPath, "--stats-every", "5s"}, args...)
	emit(scan.Event{Type: "log", Message: "$ " + CommandString(args)})

	cmd := exec.CommandContext(ctx, info.Path, full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := progressRe.FindStringSubmatch(line); m != nil {
			if pct, err := strconv.ParseFloat(m[1], 64); err == nil {
				emit(scan.Event{Type: "progress", Done: int(pct * 10), Total: 1000})
			}
		}
		emit(scan.Event{Type: "log", Message: line})
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	data, err := os.ReadFile(tmpPath)
	if err == nil && len(data) > 0 {
		hosts, perr := ParseXML(data)
		if perr != nil {
			emit(scan.Event{Type: "log", Message: "解析 XML 结果失败：" + perr.Error()})
		}
		for i := range hosts {
			h := hosts[i]
			emit(scan.Event{Type: "host", Host: &h})
			for j := range h.Ports {
				p := h.Ports[j]
				emit(scan.Event{Type: "port", Port: &p})
			}
		}
	}
	emit(scan.Event{Type: "progress", Done: 1000, Total: 1000})
	if waitErr != nil {
		return fmt.Errorf("nmap 退出异常：%v", waitErr)
	}
	return nil
}

// ---- XML 解析 ----

type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"state"`
		Service struct {
			Name      string `xml:"name,attr"`
			Product   string `xml:"product,attr"`
			Version   string `xml:"version,attr"`
			ExtraInfo string `xml:"extrainfo,attr"`
		} `xml:"service"`
		Scripts []struct {
			ID     string `xml:"id,attr"`
			Output string `xml:"output,attr"`
		} `xml:"script"`
	} `xml:"ports>port"`
	OSMatches []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
	} `xml:"os>osmatch"`
}

// ParseXML 解析 nmap -oX 输出。
func ParseXML(data []byte) ([]scan.HostResult, error) {
	var run xmlRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []scan.HostResult
	for _, h := range run.Hosts {
		hr := scan.HostResult{State: h.Status.State}
		for _, a := range h.Addresses {
			if a.AddrType != "mac" && hr.Address == "" {
				hr.Address = a.Addr
			}
		}
		if len(h.Hostnames) > 0 {
			hr.Hostname = h.Hostnames[0].Name
		}
		if len(h.OSMatches) > 0 {
			hr.OS = fmt.Sprintf("%s (%s%%)", h.OSMatches[0].Name, h.OSMatches[0].Accuracy)
		}
		for _, p := range h.Ports {
			version := strings.TrimSpace(p.Service.Version + " " + p.Service.ExtraInfo)
			var scripts []string
			for _, s := range p.Scripts {
				scripts = append(scripts, s.ID+": "+strings.Join(strings.Fields(s.Output), " "))
			}
			hr.Ports = append(hr.Ports, scan.PortResult{
				Host: hr.Address, Port: p.PortID, Proto: p.Protocol,
				State: p.State.State, Reason: p.State.Reason,
				Service: p.Service.Name, Product: p.Service.Product, Version: version,
				Banner: strings.Join(scripts, " | "),
			})
		}
		out = append(out, hr)
	}
	return out, nil
}
