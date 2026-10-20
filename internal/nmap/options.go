// Package nmap 负责把界面选项转换成 nmap 参数、执行 nmap 并解析 XML 结果。
package nmap

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Options 对应界面上的 nmap 选项。
type Options struct {
	Targets string `json:"targets"`

	// 扫描技术：sS sT sU sA sW sM sN sF sX sn（仅主机发现）
	ScanType string `json:"scanType"`
	// 额外同时进行 UDP 扫描（与 TCP 类型组合，如 -sS -sU）
	AlsoUDP bool `json:"alsoUdp"`

	// 端口
	Ports    string `json:"ports"`    // -p
	TopPorts int    `json:"topPorts"` // --top-ports
	AllPorts bool   `json:"allPorts"` // -p-
	Fast     bool   `json:"fast"`     // -F

	// 主机发现
	NoPing bool `json:"noPing"` // -Pn
	NoDNS  bool `json:"noDns"`  // -n

	// 服务与系统探测
	Version          bool `json:"version"`          // -sV
	VersionIntensity int  `json:"versionIntensity"` // --version-intensity 0-9, -1 表示不设置
	OS               bool `json:"os"`               // -O
	Aggressive       bool `json:"aggressive"`       // -A
	Traceroute       bool `json:"traceroute"`       // --traceroute

	// 脚本
	DefaultScripts bool     `json:"defaultScripts"` // -sC
	Scripts        []string `json:"scripts"`        // --script a,b
	ScriptArgs     string   `json:"scriptArgs"`     // --script-args

	// 时序与性能
	Timing      int    `json:"timing"`      // -T0..-T5，-1 表示不设置
	MinRate     int    `json:"minRate"`     // --min-rate
	MaxRetries  int    `json:"maxRetries"`  // --max-retries，-1 表示不设置
	HostTimeout string `json:"hostTimeout"` // --host-timeout 如 30s / 5m

	// 规避与杂项
	Fragment bool `json:"fragment"` // -f
	IPv6     bool `json:"ipv6"`     // -6
	OpenOnly bool `json:"openOnly"` // --open
	Reason   bool `json:"reason"`   // --reason
	Verbose  bool `json:"verbose"`  // -v

	// 额外参数（高级用户），会做安全检查
	Extra string `json:"extra"`
}

var (
	scanTypes = map[string]bool{"sS": true, "sT": true, "sU": true, "sA": true, "sW": true, "sM": true, "sN": true, "sF": true, "sX": true, "sn": true}
	// 目标只允许 IP、CIDR、范围、域名使用的字符，且不能以 - 开头（防止参数注入）
	targetRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:/\-_,]*$`)
	portsRe      = regexp.MustCompile(`^[0-9TUSPtusp:,\-]+$`)
	scriptRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-*]*$`)
	timeRe       = regexp.MustCompile(`^[0-9]+(ms|s|m|h)?$`)
	scriptArgsRe = regexp.MustCompile(`^[A-Za-z0-9_.\-=,{}'" /:]+$`)

	// 禁止通过额外参数使用的选项：读写文件、改变数据目录等
	forbiddenPrefixes = []string{"-o", "-i", "--resume", "--datadir", "--servicedb", "--versiondb",
		"--stylesheet", "--script", "--excludefile", "--append-output", "--privileged", "--unprivileged",
		"--interactive", "--send-eth", "-e"}
)

// RequiresRoot 判断选项是否需要 root 权限。
func (o Options) RequiresRoot() bool {
	switch o.ScanType {
	case "sS", "sU", "sA", "sW", "sM", "sN", "sF", "sX":
		return true
	}
	return o.AlsoUDP || o.OS || o.Aggressive || o.Fragment || o.Traceroute
}

// BuildArgs 把选项转换成 nmap 参数（不包含输出参数）。
func BuildArgs(o Options) ([]string, error) {
	var args []string
	add := func(a ...string) { args = append(args, a...) }

	st := o.ScanType
	if st == "" {
		st = "sT"
	}
	if !scanTypes[st] {
		return nil, fmt.Errorf("不支持的扫描类型：%s", st)
	}
	add("-" + st)
	if o.AlsoUDP && st != "sU" && st != "sn" {
		add("-sU")
	}

	if st != "sn" {
		switch {
		case o.AllPorts:
			add("-p-")
		case strings.TrimSpace(o.Ports) != "":
			p := strings.ReplaceAll(strings.TrimSpace(o.Ports), " ", "")
			if !portsRe.MatchString(p) {
				return nil, fmt.Errorf("端口格式无效：%s", o.Ports)
			}
			add("-p", p)
		case o.TopPorts > 0:
			if o.TopPorts > 65535 {
				return nil, fmt.Errorf("top-ports 超出范围")
			}
			add("--top-ports", strconv.Itoa(o.TopPorts))
		case o.Fast:
			add("-F")
		}
	}

	if o.NoPing {
		add("-Pn")
	}
	if o.NoDNS {
		add("-n")
	}
	if o.Version && st != "sn" {
		add("-sV")
		if o.VersionIntensity >= 0 && o.VersionIntensity <= 9 && o.VersionIntensity != 7 {
			add("--version-intensity", strconv.Itoa(o.VersionIntensity))
		}
	}
	if o.OS {
		add("-O")
	}
	if o.Aggressive {
		add("-A")
	}
	if o.Traceroute {
		add("--traceroute")
	}
	if o.DefaultScripts {
		add("-sC")
	}
	if len(o.Scripts) > 0 {
		for _, s := range o.Scripts {
			if !scriptRe.MatchString(s) {
				return nil, fmt.Errorf("脚本名称无效：%s", s)
			}
		}
		add("--script", strings.Join(o.Scripts, ","))
		if strings.TrimSpace(o.ScriptArgs) != "" {
			if !scriptArgsRe.MatchString(o.ScriptArgs) {
				return nil, fmt.Errorf("脚本参数包含不允许的字符")
			}
			add("--script-args", strings.TrimSpace(o.ScriptArgs))
		}
	}
	if o.Timing >= 0 && o.Timing <= 5 {
		add("-T" + strconv.Itoa(o.Timing))
	}
	if o.MinRate > 0 {
		add("--min-rate", strconv.Itoa(o.MinRate))
	}
	if o.MaxRetries >= 0 && o.MaxRetries <= 50 {
		add("--max-retries", strconv.Itoa(o.MaxRetries))
	}
	if ht := strings.TrimSpace(o.HostTimeout); ht != "" {
		if !timeRe.MatchString(ht) {
			return nil, fmt.Errorf("主机超时格式无效（示例：30s、5m）")
		}
		add("--host-timeout", ht)
	}
	if o.Fragment {
		add("-f")
	}
	if o.IPv6 {
		add("-6")
	}
	if o.OpenOnly {
		add("--open")
	}
	if o.Reason {
		add("--reason")
	}
	if o.Verbose {
		add("-v")
	}

	if extra := strings.Fields(o.Extra); len(extra) > 0 {
		for _, tok := range extra {
			for _, f := range forbiddenPrefixes {
				if strings.HasPrefix(tok, f) && looksLikeOption(tok, f) {
					return nil, fmt.Errorf("出于安全考虑，额外参数中不允许使用 %s", tok)
				}
			}
			if strings.ContainsAny(tok, ";|&`$<>\\") {
				return nil, fmt.Errorf("额外参数包含不允许的字符：%s", tok)
			}
		}
		add(extra...)
	}

	targets := strings.Fields(strings.ReplaceAll(o.Targets, ",", " "))
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标不能为空")
	}
	for _, t := range targets {
		if !targetRe.MatchString(t) {
			return nil, fmt.Errorf("目标格式无效：%s", t)
		}
	}
	add(targets...)
	return args, nil
}

// looksLikeOption 避免误伤，例如禁止 "-o" 前缀时不误伤 "--open"（以 "--" 开头的长选项单独列出）。
func looksLikeOption(tok, prefix string) bool {
	if strings.HasPrefix(prefix, "--") {
		return true
	}
	// 短选项前缀（-o -i -e）只匹配不以 "--" 开头的 token
	return !strings.HasPrefix(tok, "--")
}

// CommandString 生成用于界面展示的命令行。
func CommandString(args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, "nmap")
	for _, a := range args {
		if strings.ContainsAny(a, " '\"{}") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
