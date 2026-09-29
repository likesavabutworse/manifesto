package manifest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const helmOutput = `---
# Source: mychart/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: web
---
# Source: mychart/charts/redis/templates/sts.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: cache
`

func TestParseChartOutput(t *testing.T) {
	rs, err := Parse([]byte(helmOutput), "", "path/to/mychart")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d resources, want 2", len(rs))
	}
	if rs[0].File != "path/to/mychart/templates/service.yaml" || rs[0].ID() != "Service/web" || rs[0].Line != 0 {
		t.Errorf("unexpected first resource: %+v", rs[0])
	}
	if rs[1].File != "path/to/mychart/charts/redis/templates/sts.yaml" || rs[1].Namespace != "cache" {
		t.Errorf("unexpected second resource: %+v", rs[1])
	}
}

func TestParseFileKeepsRealLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "all.yaml")
	if err := os.WriteFile(path, []byte(helmOutput), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].File != path || rs[0].Line != 3 || rs[1].Line != 9 {
		t.Errorf("want real file and lines 3, 9; got %s:%d, %s:%d", rs[0].File, rs[0].Line, rs[1].File, rs[1].Line)
	}
}

func TestParseSkipsNonObjects(t *testing.T) {
	rs, err := Parse([]byte("---\n# just a comment\n---\nfoo: bar\n---\n- a\n"), "x.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 0 {
		t.Errorf("want no resources, got %+v", rs)
	}
}

func writeChart(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRenderChart(t *testing.T) {
	dir := writeChart(t, map[string]string{
		"Chart.yaml":  "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
		"values.yaml": "replicas: 1\n",
		"templates/cm.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-cfg
  namespace: {{ .Release.Namespace }}
data:
  replicas: {{ .Values.replicas | quote }}
`,
		"templates/tests/t.yaml": `apiVersion: v1
kind: Pod
metadata:
  name: t
  annotations: {"helm.sh/hook": test}
spec: {containers: [{name: t, image: busybox}]}
`,
		"templates/job.yaml": `apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
  annotations: {"helm.sh/hook": pre-install}
spec: {template: {spec: {restartPolicy: Never, containers: [{name: m, image: app:1}]}}}
`,
	})
	rs, err := RenderChart(context.Background(), dir, RenderOptions{Release: "r", Namespace: "ns", Set: []string{"replicas=3"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, r.ID()+"@"+strings.TrimPrefix(r.File, dir+"/"))
	}
	if strings.Join(got, ",") != "ConfigMap/r-cfg@templates/cm.yaml,Job/migrate@templates/job.yaml" {
		t.Errorf("got %v (test hooks should be skipped, other hooks kept)", got)
	}
	if rs[0].Namespace != "ns" || rs[0].Object["data"].(map[string]any)["replicas"] != "3" {
		t.Errorf("--namespace/--set not applied: %+v", rs[0])
	}

	rs, err = RenderChart(context.Background(), dir, RenderOptions{IncludeTests: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Errorf("IncludeTests: got %d resources, want 3", len(rs))
	}
}

func TestRenderChartErrors(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"helm dependency build": {
			"Chart.yaml": "apiVersion: v2\nname: demo\nversion: 0.1.0\ndependencies:\n- name: redis\n  version: 1.0.0\n  repository: https://example.com\n",
		},
		"library chart": {
			"Chart.yaml": "apiVersion: v2\nname: lib\nversion: 0.1.0\ntype: library\n",
		},
		"required": {
			"Chart.yaml":       "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
			"templates/x.yaml": "{{ required \"required: image.tag must be set\" .Values.image }}\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RenderChart(context.Background(), writeChart(t, files), RenderOptions{})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("want an error mentioning %q, got %v", name, err)
			}
		})
	}
}
