package pss

import (
	"sort"
	"strings"
	"testing"
)

func deployment(pod map[string]any) map[string]any {
	return map[string]any{
		"kind": "Deployment",
		"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{}, "spec": pod}},
	}
}

func ids(vs []Violation) string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Check.ID)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// hardened passes restricted; each case breaks one thing.
func hardened() map[string]any {
	return map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers": []any{map[string]any{
			"name": "app", "image": "app:1",
			"securityContext": map[string]any{
				"allowPrivilegeEscalation": false,
				"capabilities":             map[string]any{"drop": []any{"ALL"}},
			},
		}},
	}
}

func TestLevels(t *testing.T) {
	bare := deployment(map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1"}}})
	if got := ids(New(Baseline).Evaluate("Deployment", bare)); got != "" {
		t.Errorf("baseline on a bare pod: got %s, want nothing", got)
	}
	want := "pss.allowPrivilegeEscalation,pss.capabilities_restricted,pss.runAsNonRoot,pss.seccompProfile_restricted"
	if got := ids(New(Restricted).Evaluate("Deployment", bare)); got != want {
		t.Errorf("restricted on a bare pod:\n got %s\nwant %s", got, want)
	}
	if got := ids(New(Restricted).Evaluate("Deployment", deployment(hardened()))); got != "" {
		t.Errorf("hardened pod: got %s, want nothing", got)
	}
	if vs := New(Off).Evaluate("Deployment", bare); len(vs) != 0 {
		t.Errorf("off: got %v", vs)
	}
}

func TestRestrictedReplacesBaselineVariant(t *testing.T) {
	for _, c := range New(Restricted).Checks {
		if c.ID == "pss.capabilities_baseline" || c.ID == "pss.seccompProfile_baseline" {
			t.Errorf("%s should be replaced by its restricted variant", c.ID)
		}
	}
}

func TestBaselineViolations(t *testing.T) {
	pod := hardened()
	pod["hostNetwork"] = true
	c := pod["containers"].([]any)[0].(map[string]any)
	c["securityContext"].(map[string]any)["privileged"] = true
	vs := New(Restricted).Evaluate("Deployment", deployment(pod))
	if got := ids(vs); got != "pss.hostNamespaces,pss.privileged" {
		t.Errorf("got %s", got)
	}
	for _, v := range vs {
		if v.Severity != "high" {
			t.Errorf("%s: baseline check severity %s, want high", v.Check.ID, v.Severity)
		}
	}
}

func TestKinds(t *testing.T) {
	cron := map[string]any{"kind": "CronJob", "spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{
		"template": map[string]any{"spec": map[string]any{"hostPID": true, "containers": []any{map[string]any{"name": "c", "image": "c:1"}}}},
	}}}}
	if got := ids(New(Baseline).Evaluate("CronJob", cron)); got != "pss.hostNamespaces" {
		t.Errorf("cronjob: got %s", got)
	}
	if vs := New(Restricted).Evaluate("ConfigMap", map[string]any{"kind": "ConfigMap"}); len(vs) != 0 {
		t.Errorf("configmap: got %v", vs)
	}
}

func TestInvalidPodSpec(t *testing.T) {
	pod := hardened()
	pod["securityContext"].(map[string]any)["runAsUser"] = "1000"
	vs := New(Restricted).Evaluate("Deployment", deployment(pod))
	if len(vs) != 1 || vs[0].Check.ID != "pss.invalid_pod_spec" {
		t.Errorf("got %v", vs)
	}
}

func TestInvalidPodMetadata(t *testing.T) {
	pod := hardened()
	pod["hostNetwork"] = true
	obj := deployment(pod)
	tmpl := obj["spec"].(map[string]any)["template"].(map[string]any)
	tmpl["metadata"] = map[string]any{"labels": map[string]any{"replicas": 3}}
	vs := New(Restricted).Evaluate("Deployment", obj)
	if len(vs) != 1 || vs[0].Check.ID != "pss.invalid_pod_spec" {
		t.Errorf("got %v", vs)
	}
}
