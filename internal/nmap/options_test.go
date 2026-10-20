package nmap

import (
	"strings"
	"testing"
)

func base() Options {
	return Options{Targets: "192.168.1.0/24", ScanType: "sS", Timing: -1, MaxRetries: -1, VersionIntensity: -1}
}

func TestBuildArgs(t *testing.T) {
	o := base()
	o.Ports = "22,80,443"
	o.Version = true
	o.Timing = 4
	o.NoPing = true
	o.Scripts = []string{"http-title", "ssl-cert"}
	args, err := BuildArgs(o)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	want := "-sS -p 22,80,443 -Pn -sV --script http-title,ssl-cert -T4 192.168.1.0/24"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestRejectInjection(t *testing.T) {
	bad := []func(*Options){
		func(o *Options) { o.Targets = "-oN /tmp/x 1.1.1.1" },
		func(o *Options) { o.Targets = "1.1.1.1;rm -rf /" },
		func(o *Options) { o.Extra = "-oN /tmp/x" },
		func(o *Options) { o.Extra = "-iL /etc/passwd" },
		func(o *Options) { o.Extra = "--script=/tmp/evil.nse" },
		func(o *Options) { o.Scripts = []string{"../evil"} },
		func(o *Options) { o.ScanType = "sZ" },
		func(o *Options) { o.Ports = "80;id" },
	}
	for i, f := range bad {
		o := base()
		f(&o)
		if _, err := BuildArgs(o); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	o := base()
	o.Extra = "--open --reason --min-hostgroup 64"
	if _, err := BuildArgs(o); err != nil {
		t.Errorf("legit extra rejected: %v", err)
	}
}
