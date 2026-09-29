package scaffold

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

func TestPackageName(t *testing.T) {
	for in, want := range map[string]string{
		"require-team-label":  "require_team_label",
		"Require Team Label":  "require_team_label",
		"  --weird!!name--  ": "weird_name",
		"already_fine":        "already_fine",
		"2fast":               "policy_2fast",
		"!!!":                 "policy_",
		"":                    "policy_",
	} {
		if got := PackageName(in); got != want {
			t.Errorf("PackageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteProducesValidRego(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "policies")
	policyPath, testPath, err := Write(dir, "No Latest", []string{"CronJob", "Job"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "no_latest.rego"); policyPath != want {
		t.Errorf("policy path %s, want %s", policyPath, want)
	}
	if want := filepath.Join(dir, "no_latest_test.rego"); testPath != want {
		t.Errorf("test path %s, want %s", testPath, want)
	}

	for _, p := range []string{policyPath, testPath} {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ast.ParseModuleWithOpts(p, string(src), ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV1}); err != nil {
			t.Errorf("%s does not parse: %v", p, err)
		}
	}

	policy, _ := os.ReadFile(policyPath)
	for _, want := range []string{"package no_latest\n", "# title: no latest", "kinds: [CronJob, Job]"} {
		if !strings.Contains(string(policy), want) {
			t.Errorf("policy is missing %q:\n%s", want, policy)
		}
	}
	test, _ := os.ReadFile(testPath)
	if !strings.Contains(string(test), `"kind": "CronJob"`) {
		t.Errorf("test should use the first kind as its sample:\n%s", test)
	}
}

func TestWriteDefaultKinds(t *testing.T) {
	policyPath, _, err := Write(t.TempDir(), "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := os.ReadFile(policyPath)
	if !strings.Contains(string(policy), "kinds: [Deployment, StatefulSet, DaemonSet]") {
		t.Errorf("default kinds missing:\n%s", policy)
	}
}

func TestWriteRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Write(dir, "dup", nil); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "dup.rego")
	if err := os.WriteFile(policyPath, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Write(dir, "Dup", nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("want an already-exists error, got %v", err)
	}
	if b, _ := os.ReadFile(policyPath); string(b) != "mine" {
		t.Errorf("existing file was overwritten: %q", b)
	}
}

func TestWriteLeavesNothingWhenTestFileExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p_test.rego"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Write(dir, "p", nil); err == nil {
		t.Fatal("want an error")
	}
	if _, err := os.Stat(filepath.Join(dir, "p.rego")); err == nil {
		t.Error("policy file was written although the test file already existed")
	}
}
