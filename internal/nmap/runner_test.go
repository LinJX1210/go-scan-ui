package nmap

import "testing"

const sampleXML = `<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Debian"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx"/><script id="http-title" output="Welcome"/></port>
</ports>
<os><osmatch name="Linux 5.X" accuracy="96"/></os>
</host>
</nmaprun>`

func TestParseXML(t *testing.T) {
	hosts, err := ParseXML([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Address != "192.168.1.10" || hosts[0].Hostname != "router.lan" {
		t.Fatalf("bad host: %+v", hosts)
	}
	if hosts[0].OS != "Linux 5.X (96%)" {
		t.Errorf("os = %q", hosts[0].OS)
	}
	if len(hosts[0].Ports) != 2 || hosts[0].Ports[0].Product != "OpenSSH" || hosts[0].Ports[0].Version != "9.6p1 Debian" {
		t.Errorf("ports = %+v", hosts[0].Ports)
	}
	if hosts[0].Ports[1].Banner != "http-title: Welcome" {
		t.Errorf("script = %q", hosts[0].Ports[1].Banner)
	}
}
