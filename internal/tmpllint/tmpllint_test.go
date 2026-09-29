package tmpllint

import (
	"strconv"
	"strings"
	"testing"
)

func TestBadChart(t *testing.T) {
	fs, err := Chart("../../testdata/charts/bad")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tmpl.hardcoded_image@cronjob.yaml:18",
		"tmpl.hardcoded_namespace@deployment.yaml:5",
		"tmpl.hardcoded_image@deployment.yaml:24",
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	for i, f := range fs {
		got := f.Policy + "@" + f.File[len("../../testdata/charts/bad/templates/"):] + ":" + strconv.Itoa(f.Line)
		if got != want[i] {
			t.Errorf("finding %d: got %s, want %s", i, got, want[i])
		}
	}
}

func TestGoodChart(t *testing.T) {
	fs, err := Chart("../../testdata/charts/good")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("want no findings, got %+v", fs)
	}
}

func TestParserEdgeCases(t *testing.T) {
	src := `{{/*
Example usage, not real YAML:
  image: nginx:latest
  namespace: example
*/}}
apiVersion: v1
kind: Pod
metadata:
  namespace: {{ .Release.Namespace }}
spec:
  containers:
    - image: "{{ .Values.repo }}:{{ .Values.tag }}"
    - image: "ghcr.io/acme/app:{{ .Values.tag }}"
    {{- if .Values.sidecar }}
    - image: envoyproxy/envoy:v1.30.0
    {{- end }}
    - image: {{- " busybox" }}
    - {{ include "x" . }}
      image: redis:7
`
	fs, err := Source("t.yaml", src)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.Policy+":"+strconv.Itoa(f.Line))
	}
	want := "tmpl.hardcoded_image:15,tmpl.hardcoded_image:19"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestUnparseableTemplateIsLeftToRender(t *testing.T) {
	fs, err := Source("broken.yaml", "image: {{ .Values.x ")
	if err != nil || len(fs) != 0 {
		t.Errorf("got %v, %v", fs, err)
	}
}

func TestSystemNamespacesAreNotFlagged(t *testing.T) {
	src := `metadata:
  namespace: kube-system
---
metadata:
  namespace: "kube-public"
---
metadata:
  namespace: kube-node-lease
---
metadata:
  namespace: payments
`
	fs, err := Source("t.yaml", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Line != 11 {
		t.Errorf("want only line 11 (payments), got %+v", fs)
	}
}

func TestIgnoreComment(t *testing.T) {
	src := `metadata:
  namespace: payments {{/* manifesto:ignore tmpl.hardcoded_namespace */}}
---
metadata:
  {{- /* manifesto:ignore tmpl.hardcoded_namespace, tmpl.hardcoded_image */}}
  namespace: payments
---
metadata:
  {{/* manifesto:ignore all */}}
  namespace: payments
---
metadata:
  {{/* manifesto:ignore tmpl.hardcoded_image */}}
  namespace: payments
---
metadata:
  {{/* an ordinary comment */}}

  namespace: payments
---
metadata:
  namespace: payments {{/* no directive here */}}
`
	fs, err := Source("t.yaml", src)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, strconv.Itoa(f.Line)+":"+strconv.FormatBool(f.Ignored))
	}
	// Ignored: trailing comment, comment above (with two IDs), "all". Not
	// ignored: a comment for another check, a comment two lines up, and a
	// trailing comment that is not a directive, which must not hide the value.
	want := "2:true,6:true,10:true,14:false,19:false,22:false"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
