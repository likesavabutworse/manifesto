package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) *List {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ignore.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestMatch(t *testing.T) {
	l := load(t, `
ignore:
  - policy: pss.hostNamespaces
    resource: DaemonSet/*-node-exporter
    reason: needs host network
  - policy: k8s.*
    file: templates/jobs/*.yaml
    reason: throwaway jobs
  - policy: tmpl.hardcoded_namespace
    namespace: kube-system
    reason: monitors CoreDNS
`)
	for _, tc := range []struct {
		policy, file, resource, ns string
		want                       bool
	}{
		{"pss.hostNamespaces", "chart/templates/ds.yaml", "DaemonSet/web-node-exporter", "", true},
		{"pss.hostNamespaces", "chart/templates/ds.yaml", "DaemonSet/web", "", false},
		{"pss.privileged", "chart/templates/ds.yaml", "DaemonSet/web-node-exporter", "", false},
		{"k8s.probes", "./deploy/chart/templates/jobs/migrate.yaml", "Job/migrate", "", true},
		{"k8s.probes", "chart/templates/deployment.yaml", "Deployment/api", "", false},
		{"tmpl.hardcoded_namespace", "chart/templates/x.yaml", "", "kube-system", true},
		{"tmpl.hardcoded_namespace", "chart/templates/x.yaml", "", "payments", false},
	} {
		if got := l.Match(tc.policy, tc.file, tc.resource, tc.ns); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
	if u := l.Unused(); len(u) != 0 {
		t.Errorf("unexpected unused entries: %v", u)
	}
}

func TestUnused(t *testing.T) {
	l := load(t, "ignore:\n  - {policy: a, reason: r}\n  - {policy: b, reason: r}\n")
	l.Match("a", "f", "", "")
	u := l.Unused()
	if len(u) != 1 || !strings.Contains(u[0], "ignore[1] (b)") {
		t.Errorf("got %v", u)
	}
}

func TestLoadErrors(t *testing.T) {
	for name, body := range map[string]string{
		"no reason":    "ignore:\n  - policy: a\n",
		"blank reason": "ignore:\n  - {policy: a, reason: '  '}\n",
		"no policy":    "ignore:\n  - reason: because\n",
		"typo":         "ignore:\n  - {policy: a, reason: r, resourse: x}\n",
		"wrong shape":  "- policy: a\n",
	} {
		p := filepath.Join(t.TempDir(), "i.yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestMissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if l, err := Load(""); err != nil || len(l.Entries) != 0 {
		t.Errorf("missing default file: %v, %v", l, err)
	}
	if _, err := Load("nope.yaml"); err == nil || !strings.Contains(err.Error(), "nope.yaml: no such file") {
		t.Errorf("missing named file: %v", err)
	}
}
