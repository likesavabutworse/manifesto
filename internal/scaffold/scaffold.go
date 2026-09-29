// Package scaffold writes a starter policy and its test, so a first custom
// rule starts from something that already runs rather than a blank file.
package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

const DefaultDir = ".manifesto/policies"

var nonIdent = regexp.MustCompile(`[^a-z0-9_]+`)

func PackageName(name string) string {
	s := nonIdent.ReplaceAllString(strings.ToLower(name), "_")
	s = strings.Trim(s, "_")
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		s = "policy_" + s
	}
	return s
}

func Write(dir, name string, kinds []string) (string, string, error) {
	pkg := PackageName(name)
	if len(kinds) == 0 {
		kinds = []string{"Deployment", "StatefulSet", "DaemonSet"}
	}
	data := struct {
		Pkg, Title, Kinds, SampleKind string
	}{
		Pkg:        pkg,
		Title:      strings.ReplaceAll(pkg, "_", " "),
		Kinds:      strings.Join(kinds, ", "),
		SampleKind: kinds[0],
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	policyPath := filepath.Join(dir, pkg+".rego")
	testPath := filepath.Join(dir, pkg+"_test.rego")
	for _, p := range []string{policyPath, testPath} {
		if _, err := os.Stat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists", p)
		}
	}
	if err := render(policyPath, policyTmpl, data); err != nil {
		return "", "", err
	}
	if err := render(testPath, testTmpl, data); err != nil {
		return "", "", err
	}
	return policyPath, testPath, nil
}

func render(path string, tmpl *template.Template, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

var policyTmpl = template.Must(template.New("policy").Parse(`# METADATA
# title: {{.Title}}
# custom:
#   severity: medium          # high | medium | low
#   kinds: [{{.Kinds}}]   # remove to run against every kind
package {{.Pkg}}

import data.manifesto.lib

# ` + "`input`" + ` is one rendered Kubernetes resource, exactly as ` + "`helm template`" + `
# printed it. Every ` + "`deny`" + ` rule whose body is true adds one finding with
# the message in ` + "`msg`" + `. Replace this example with your own condition(s).
#
# Handy helpers from data.manifesto.lib:
#   lib.containers, lib.init_containers, lib.all_containers, lib.pod_spec
#   lib.has_label(key), lib.has_annotation(key), lib.name  ("Kind/name")
# print(...) output shows up on stderr while scanning — use it to debug.

deny contains msg if {
	not lib.has_label("team")
	msg := sprintf("%s has no \"team\" label", [lib.name])
}

# Findings can also carry a path and override the severity:
#
# deny contains {"msg": msg, "path": "spec.replicas", "severity": "low"} if {
# 	input.spec.replicas < 2
# 	msg := "a single replica can't survive a node drain"
# }
`))

var testTmpl = template.Must(template.New("test").Parse(`# Run with: manifesto test
package {{.Pkg}}_test

import data.{{.Pkg}}

test_flags_missing_label if {
	count({{.Pkg}}.deny) == 1 with input as {
		"kind": "{{.SampleKind}}",
		"metadata": {"name": "web"},
	}
}

test_passes_with_label if {
	count({{.Pkg}}.deny) == 0 with input as {
		"kind": "{{.SampleKind}}",
		"metadata": {"name": "web", "labels": {"team": "payments"}},
	}
}
`))
