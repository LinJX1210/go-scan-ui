package scan

import "testing"

func TestParseTargets(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"192.168.1.1", 1},
		{"192.168.1.0/24", 254},
		{"192.168.1.0/30", 2},
		{"10.0.0.1-10", 10},
		{"10.0.0.1-10.0.0.5, example.com", 6},
		{"10.0.0.1 10.0.0.1", 1},
	}
	for _, c := range cases {
		got, err := ParseTargets(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if len(got) != c.want {
			t.Errorf("%q: got %d hosts, want %d", c.in, len(got), c.want)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/8", "-oN", "1.2.3.4-1.2.3.1", "a..b"} {
		if _, err := ParseTargets(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80, 22,443,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	for _, bad := range []string{"0", "65536", "100-1", "abc"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestServiceFromBanner(t *testing.T) {
	for b, want := range map[string]string{
		"SSH-2.0-OpenSSH_9.6": "ssh", "HTTP/1.1 200 OK": "http", "220 ProFTPD Server": "ftp",
		"RFB 003.008": "vnc", "": "", "random": "",
	} {
		if got := ServiceFromBanner(b); got != want {
			t.Errorf("%q: got %q want %q", b, got, want)
		}
	}
}
