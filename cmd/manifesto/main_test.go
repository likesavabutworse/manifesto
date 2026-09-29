package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scanJSON(t *testing.T, args ...string) (int, []map[string]any) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"scan", "-o", "json"}, args...), &out, &errOut)
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("bad JSON (stderr: %s): %v\n%s", errOut.String(), err, out.String())
	}
	return code, doc.Findings
}

func TestScanBadChart(t *testing.T) {
	code, fs := scanJSON(t, "../../testdata/charts/bad")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f["policy"].(string)]++
	}
	want := map[string]int{
		"k8s.image_tag": 3, "k8s.probes": 2,
		"k8s.resources":      2, // the CronJob's is ignored by its manifesto.io/ignore annotation
		"pss.hostNamespaces": 1, "pss.privileged": 1, "pss.runAsUser": 1, "pss.runAsNonRoot": 1,
		"pss.allowPrivilegeEscalation": 2, "pss.capabilities_restricted": 2, "pss.seccompProfile_restricted": 2,
		"k8s.default_service_account": 2, "k8s.readonly_rootfs": 3,
		"tmpl.hardcoded_image": 2, "tmpl.hardcoded_namespace": 1,
	}
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("%s: got %d findings, want %d", id, counts[id], n)
		}
	}
	if len(counts) != len(want) {
		t.Errorf("unexpected policies in %v", counts)
	}
}

func TestScanGoodChart(t *testing.T) {
	code, fs := scanJSON(t, "../../testdata/charts/good")
	if code != 0 || len(fs) != 0 {
		t.Errorf("exit %d with %d findings, want a clean pass: %v", code, len(fs), fs)
	}
}

func TestFailOnAndIgnore(t *testing.T) {
	if code, _ := scanJSON(t, "../../testdata/charts/bad", "--fail-on", "never"); code != 0 {
		t.Errorf("--fail-on never: exit %d", code)
	}
	_, fs := scanJSON(t, "../../testdata/charts/bad", "--ignore", "k8s.image_tag,tmpl.hardcoded_image")
	for _, f := range fs {
		if p := f["policy"]; p == "k8s.image_tag" || p == "tmpl.hardcoded_image" {
			t.Errorf("--ignore left %v", f)
		}
	}
}

func TestNewThenTestThenScan(t *testing.T) {
	chart, err := filepath.Abs("../../testdata/charts/good")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	var out, errOut bytes.Buffer
	if code := run([]string{"new", "Require Team Label", "--kind", "StatefulSet"}, &out, &errOut); code != 0 {
		t.Fatalf("new: exit %d: %s", code, errOut.String())
	}
	if code := run([]string{"new", "require-team-label"}, &out, &errOut); code != 2 {
		t.Errorf("new over an existing policy: exit %d, want 2", code)
	}
	out.Reset()
	if code := run([]string{"test"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "2 passed, 0 failed") {
		t.Fatalf("test: exit %d: %s", code, out.String())
	}
	code, fs := scanJSON(t, chart)
	if code != 1 || len(fs) != 1 || fs[0]["policy"] != "require_team_label" {
		t.Fatalf("scan: exit %d, findings %v", code, fs)
	}
}

func TestPSSBaseline(t *testing.T) {
	_, fs := scanJSON(t, "../../testdata/charts/bad", "--pss", "baseline")
	for _, f := range fs {
		p := f["policy"].(string)
		if strings.HasPrefix(p, "pss.") && p != "pss.hostNamespaces" && p != "pss.privileged" {
			t.Errorf("--pss baseline reported restricted check %s", p)
		}
	}
}

func TestSARIFOutput(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"scan", "-o", "sarif", "../../testdata/charts/bad"}, &out, &bytes.Buffer{}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || !strings.Contains(out.String(), "pss.privileged") {
		t.Errorf("unexpected SARIF:\n%.500s", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"scan", "--fail-on", "sometimes", "."},
		{"scan", "-o", "xml", "."},
		{"scan", "--pss", "strict", "."},
		{"scan", "a", "b"},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestMain(m *testing.M) {
	os.Setenv("NO_COLOR", "1")
	os.Exit(m.Run())
}

func TestScanWithValidatingAdmissionPolicy(t *testing.T) {
	dir := t.TempDir()
	rendered := filepath.Join(dir, "web.yaml")
	if err := os.WriteFile(rendered, []byte(`apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 1
  template:
    spec:
      containers: [{name: app, image: ghcr.io/acme/app:1}]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, fs := scanJSON(t, rendered, "--no-builtins", "--pss", "off", "-p", "../../examples/policies")
	got := map[string]string{}
	for _, f := range fs {
		got[f["policy"].(string)] = f["severity"].(string)
	}
	// min-replicas fails (1 replica); no-hostpath and image-registry pass. The
	// examples directory also holds Rego policies, which run alongside.
	if code != 1 || got["min-replicas"] != "medium" {
		t.Fatalf("exit %d, findings %v", code, fs)
	}
	if _, ok := got["no-hostpath"]; ok {
		t.Errorf("no-hostpath should pass: %v", fs)
	}
	if _, ok := got["image-registry"]; ok {
		t.Errorf("image-registry should pass for ghcr.io/acme: %v", fs)
	}
}

func TestMultipleOutputs(t *testing.T) {
	sarifPath := filepath.Join(t.TempDir(), "out.sarif")
	var out bytes.Buffer
	code := run([]string{"scan", "-o", "text", "-o", "sarif=" + sarifPath, "../../testdata/charts/bad"}, &out, &bytes.Buffer{})
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "pss.privileged") || strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Errorf("stdout should hold only the text report:\n%.300s", out.String())
	}
	b, err := os.ReadFile(sarifPath)
	if err != nil || !strings.Contains(string(b), `"version": "2.1.0"`) {
		t.Errorf("SARIF file: %v\n%.300s", err, b)
	}
}

func TestOutputUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "-o", "text,sarif", "."},
		{"scan", "-o", "text", "-o", "json", "."},
		{"scan", "-o", "xml=x", "."},
	} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func runScanErr(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"scan"}, args...), &out, &errOut)
	return code, errOut.String()
}

func TestNothingToScanIsAnError(t *testing.T) {
	empty := t.TempDir()
	notK8s := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(notK8s, []byte("replicas: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{empty, notK8s} {
		code, msg := runScanErr(t, target)
		if code != 2 || !strings.Contains(msg, "no Kubernetes resources found in "+target) {
			t.Errorf("%s: exit %d, stderr %q", target, code, msg)
		}
	}
}

func TestChartThatRendersNothingWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: idle\nversion: 0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, msg := runScanErr(t, dir)
	if code != 0 || !strings.Contains(msg, "renders no resources") {
		t.Errorf("exit %d, stderr %q", code, msg)
	}
}

func TestMissingFilesNameThePath(t *testing.T) {
	for _, tc := range [][]string{
		{"nonexistent"},
		{"../../testdata/charts/good", "-f", "nofile.yaml"},
	} {
		code, msg := runScanErr(t, tc...)
		if code != 2 || strings.Contains(msg, "open ") || strings.Contains(msg, "stat ") || !strings.Contains(msg, "no such file or directory") {
			t.Errorf("%v: exit %d, stderr %q", tc, code, msg)
		}
	}
}

func TestCELPolicyTests(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"test", "-p", "../../examples/policies"}, &out, &bytes.Buffer{}); code != 0 || !strings.Contains(out.String(), "0 failed") {
		t.Fatalf("examples: exit %d\n%s", code, out.String())
	}

	dir := t.TempDir()
	policy, err := os.ReadFile("../../examples/policies/min_replicas.yaml")
	if err != nil {
		t.Fatal(err)
	}
	broken := `apiVersion: manifesto.io/v1
kind: PolicyTest
policy: min-replicas
cases:
  - name: three replicas, wrongly expected to fail
    expect: fail
    object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 3}}
`
	for name, body := range map[string]string{"policy.yaml": string(policy), "policy_test.yaml": broken} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if code := run([]string{"test", "-p", dir}, &out, &bytes.Buffer{}); code != 1 || !strings.Contains(out.String(), "FAIL  min-replicas: three replicas") {
		t.Errorf("failing CEL test: exit %d\n%s", code, out.String())
	}
}

func TestIgnoreFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ignore.yaml")
	if err := os.WriteFile(file, []byte(`ignore:
  - policy: pss.privileged
    resource: Deployment/*-api
    reason: the proxy sidecar needs it
  - policy: tmpl.hardcoded_image
    file: templates/cronjob.yaml
    reason: pinned by the platform team
  - policy: k8s.nothing
    reason: matches nothing, so it should be reported
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "-o", "json", "--ignore-file", file, "../../testdata/charts/bad"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Findings []struct{ Policy, File string }
		Summary  struct{ Ignored int }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.Policy == "pss.privileged" || (f.Policy == "tmpl.hardcoded_image" && strings.HasSuffix(f.File, "cronjob.yaml")) {
			t.Errorf("finding was not ignored: %+v", f)
		}
	}
	// The Deployment's own hardcoded image is a different file, so it stays.
	hardcoded := 0
	for _, f := range doc.Findings {
		if f.Policy == "tmpl.hardcoded_image" {
			hardcoded++
		}
	}
	if hardcoded != 1 {
		t.Errorf("tmpl.hardcoded_image: got %d findings, want 1 (the Deployment's)", hardcoded)
	}
	if doc.Summary.Ignored < 2 {
		t.Errorf("summary counts %d ignored, want at least 2", doc.Summary.Ignored)
	}
	if !strings.Contains(errOut.String(), "ignore[2] (k8s.nothing) matched no finding") {
		t.Errorf("no warning about the unused entry: %q", errOut.String())
	}
}

func TestIgnoreFileErrors(t *testing.T) {
	noReason := filepath.Join(t.TempDir(), "ignore.yaml")
	if err := os.WriteFile(noReason, []byte("ignore:\n  - policy: k8s.probes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{noReason, "missing.yaml"} {
		if code, msg := runScanErr(t, "--ignore-file", path, "../../testdata/charts/good"); code != 2 || msg == "" {
			t.Errorf("%s: exit %d, stderr %q", path, code, msg)
		}
	}
}

func TestIgnoreCommentInTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: c\nversion: 0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cm := `apiVersion: v1
kind: ConfigMap
metadata:
  name: x
  namespace: payments {{/* manifesto:ignore tmpl.hardcoded_namespace */}}
`
	if err := os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte(cm), 0o644); err != nil {
		t.Fatal(err)
	}
	code, fs := scanJSON(t, dir)
	if code != 0 || len(fs) != 0 {
		t.Errorf("exit %d, findings %v", code, fs)
	}
}
