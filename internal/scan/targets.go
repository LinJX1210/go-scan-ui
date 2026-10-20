package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// MaxHosts 限制单次原生扫描可展开的主机数量，防止误输入超大网段。
const MaxHosts = 65536

// ParseTargets 解析目标列表，支持：
//   - 单个 IP：192.168.1.10
//   - CIDR：192.168.1.0/24
//   - 范围：192.168.1.10-20 或 192.168.1.10-192.168.1.20
//   - 域名：example.com
//
// 多个目标可用逗号、空格或换行分隔。
func ParseTargets(input string) ([]string, error) {
	fields := splitList(input)
	if len(fields) == 0 {
		return nil, fmt.Errorf("目标不能为空")
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) error {
		if seen[h] {
			return nil
		}
		if len(out) >= MaxHosts {
			return fmt.Errorf("目标主机数量超过上限 %d", MaxHosts)
		}
		seen[h] = true
		out = append(out, h)
		return nil
	}

	for _, f := range fields {
		switch {
		case strings.Contains(f, "/"):
			ip, ipnet, err := net.ParseCIDR(f)
			if err != nil {
				return nil, fmt.Errorf("无效的 CIDR：%s", f)
			}
			if ip.To4() == nil {
				return nil, fmt.Errorf("原生模式暂只支持 IPv4 网段：%s", f)
			}
			ones, bits := ipnet.Mask.Size()
			if bits-ones > 16 {
				return nil, fmt.Errorf("网段过大（最大 /16）：%s", f)
			}
			start := ipToUint(ipnet.IP.To4())
			size := uint32(1) << uint(bits-ones)
			for i := uint32(0); i < size; i++ {
				// /31、/32 之外跳过网络地址和广播地址
				if size > 2 && (i == 0 || i == size-1) {
					continue
				}
				if err := add(uintToIP(start + i).String()); err != nil {
					return nil, err
				}
			}
		case strings.Contains(f, "-") && net.ParseIP(strings.SplitN(f, "-", 2)[0]) != nil:
			parts := strings.SplitN(f, "-", 2)
			startIP := net.ParseIP(parts[0]).To4()
			if startIP == nil {
				return nil, fmt.Errorf("原生模式暂只支持 IPv4 范围：%s", f)
			}
			var endIP net.IP
			if n, err := strconv.Atoi(parts[1]); err == nil {
				if n < 0 || n > 255 {
					return nil, fmt.Errorf("无效的范围：%s", f)
				}
				endIP = make(net.IP, 4)
				copy(endIP, startIP)
				endIP[3] = byte(n)
			} else {
				endIP = net.ParseIP(parts[1]).To4()
				if endIP == nil {
					return nil, fmt.Errorf("无效的范围：%s", f)
				}
			}
			s, e := ipToUint(startIP), ipToUint(endIP)
			if e < s {
				return nil, fmt.Errorf("范围结束地址小于起始地址：%s", f)
			}
			if e-s >= MaxHosts {
				return nil, fmt.Errorf("范围过大：%s", f)
			}
			for i := s; i <= e; i++ {
				if err := add(uintToIP(i).String()); err != nil {
					return nil, err
				}
				if i == ^uint32(0) {
					break
				}
			}
		default:
			if net.ParseIP(f) == nil && !isValidHostname(f) {
				return nil, fmt.Errorf("无效的目标：%s", f)
			}
			if err := add(f); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// ParsePorts 解析端口表达式，如 "22,80,443,8000-8100"。
func ParsePorts(input string) ([]int, error) {
	fields := splitList(input)
	if len(fields) == 0 {
		return nil, fmt.Errorf("端口不能为空")
	}
	set := map[int]bool{}
	for _, f := range fields {
		if strings.Contains(f, "-") {
			parts := strings.SplitN(f, "-", 2)
			a, err1 := strconv.Atoi(parts[0])
			b, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("无效的端口范围：%s", f)
			}
			for p := a; p <= b; p++ {
				set[p] = true
			}
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("无效的端口：%s", f)
		}
		set[p] = true
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	})
}

func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func ipToUint(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func uintToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
