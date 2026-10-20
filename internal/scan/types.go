// Package scan 包含 Go 原生扫描实现与通用结果类型。
package scan

// PortResult 表示单个端口的扫描结果。
type PortResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// HostResult 表示单个主机的扫描结果。
type HostResult struct {
	Address  string       `json:"address"`
	Hostname string       `json:"hostname,omitempty"`
	State    string       `json:"state"`
	OS       string       `json:"os,omitempty"`
	Ports    []PortResult `json:"ports,omitempty"`
}

// Event 是推送给前端的扫描事件。
//
// Type 取值：log / host / port / progress / done / error
type Event struct {
	Type    string      `json:"type"`
	Message string      `json:"message,omitempty"`
	Host    *HostResult `json:"hostResult,omitempty"`
	Port    *PortResult `json:"portResult,omitempty"`
	Done    int         `json:"done,omitempty"`
	Total   int         `json:"total,omitempty"`
}

// Emitter 接收扫描过程中产生的事件。
type Emitter func(Event)
