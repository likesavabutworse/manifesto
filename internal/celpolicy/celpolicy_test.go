package celpolicy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func load(t *testing.T, files map[string]string) *Engine {
	t.Helper()
	e, err := Load([]string{write(t, files)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func deployment(replicas any, labels map[string]any) map[string]any {
	meta := map[string]any{"name": "web"}
	if labels != nil {
		meta["labels"] = labels
	}
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta,
		"spec": map[string]any{"replicas": replicas, "template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": "registry.example.com/app:1"}},
		}}},
	}
}

const replicasPolicy = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: min-replicas
  annotations:
    manifesto.io/severity: high
spec:
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      resources: ["deployments"]
  validations:
  - expression: "object.spec.replicas >= 2"
    message: "run at least 2 replicas"
`

func TestValidationAndSeverity(t *testing.T) {
	e := load(t, map[string]string{"p.yaml": replicasPolicy})
	// 1 arrives as a float64, as rendered charts do after a JSON round trip.
	vs, err := e.Eval(context.Background(), deployment(float64(1), nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Message != "run at least 2 replicas" || vs[0].Severity != "high" || vs[0].Policy.ID != "min-replicas" {
		t.Fatalf("got %+v", vs)
	}
	vs, err = e.Eval(context.Background(), deployment(float64(2), nil))
	if err != nil || len(vs) != 0 {
		t.Fatalf("2 replicas should pass: %+v, %v", vs, err)
	}
}

func TestMatching(t *testing.T) {
	e := load(t, map[string]string{"p.yaml": replicasPolicy})
	for name, obj := range map[string]map[string]any{
		"other kind":  {"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "c"}},
		"other group": {"apiVersion": "extensions/v1", "kind": "Deployment", "metadata": map[string]any{"name": "c"}},
	} {
		if vs, err := e.Eval(context.Background(), obj); err != nil || len(vs) != 0 {
			t.Errorf("%s: want no match, got %+v, %v", name, vs, err)
		}
	}
	for kind, want := range map[string]string{
		"Ingress": "ingresses", "NetworkPolicy": "networkpolicies", "Gateway": "gateways",
		"Pod": "pods", "Endpoints": "endpoints", "StorageClass": "storageclasses",
	} {
		if got := pluralize(kind); got != want {
			t.Errorf("pluralize(%s) = %s, want %s", kind, got, want)
		}
	}
}

func TestBindingParamsVariablesMessageExpression(t *testing.T) {
	e := load(t, map[string]string{"p.yaml": `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: registry-allowlist
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      resources: ["deployments"]
  matchConditions:
  - name: not-exempt
    expression: "!has(object.metadata.labels) || !('exempt' in object.metadata.labels)"
  variables:
  - name: images
    expression: "object.spec.template.spec.containers.map(c, c.image)"
  validations:
  - expression: "variables.images.all(i, params.data.registry in [i.split('/')[0]])"
    messageExpression: "'images must come from ' + params.data.registry + ', got ' + variables.images.join(',')"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: registry-allowlist-binding
spec:
  policyName: registry-allowlist
  validationActions: [Deny]
  paramRef:
    name: allowed
    parameterNotFoundAction: Deny
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: allowed
data:
  registry: ghcr.io
`})
	vs, err := e.Eval(context.Background(), deployment(float64(2), nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Message != "images must come from ghcr.io, got registry.example.com/app:1" || vs[0].Severity != "medium" {
		t.Fatalf("got %+v", vs)
	}
	vs, err = e.Eval(context.Background(), deployment(float64(2), map[string]any{"exempt": "true"}))
	if err != nil || len(vs) != 0 {
		t.Fatalf("matchConditions should exempt: %+v, %v", vs, err)
	}
}

func TestWarnOnlyBindingIsLowAndMissingParamsReported(t *testing.T) {
	e := load(t, map[string]string{"p.yaml": strings.Replace(replicasPolicy, "    manifesto.io/severity: high\n", "", 1) + `
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata: {name: b}
spec:
  policyName: min-replicas
  validationActions: [Warn, Audit]
`})
	vs, _ := e.Eval(context.Background(), deployment(float64(1), nil))
	if len(vs) != 1 || vs[0].Severity != "low" {
		t.Fatalf("warn-only policy should report low, got %+v", vs)
	}
}

func TestEvaluationErrorIsAFinding(t *testing.T) {
	e := load(t, map[string]string{"p.yaml": `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: needs-label}
spec:
  matchConstraints:
    resourceRules:
    - {apiGroups: ["apps"], apiVersions: ["v1"], resources: ["deployments"]}
  validations:
  - expression: "object.metadata.labels.team != ''"
`})
	vs, err := e.Eval(context.Background(), deployment(float64(2), nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || !strings.Contains(vs[0].Message, "failed") {
		t.Fatalf("a missing key should be reported as a finding, as a cluster would deny it: %+v", vs)
	}
}

func TestLoadErrors(t *testing.T) {
	for name, tc := range map[string]struct{ file, want string }{
		"authorizer": {`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: x}
spec:
  matchConstraints:
    resourceRules:
    - {apiGroups: ["*"], apiVersions: ["*"], resources: ["*"]}
  validations:
  - expression: "authorizer.group('').resource('pods').check('get').allowed()"
`, "without a cluster"},
		"bad severity": {`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: x, annotations: {manifesto.io/severity: critical}}
spec:
  matchConstraints:
    resourceRules:
    - {apiGroups: ["*"], apiVersions: ["*"], resources: ["*"]}
  validations:
  - expression: "true"
`, "want high, medium, or low"},
		"unknown policy in binding": {`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata: {name: b}
spec: {policyName: nope, validationActions: [Deny]}
`, `"nope"`},
		"syntax error": {`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: x}
spec:
  matchConstraints:
    resourceRules:
    - {apiGroups: ["*"], apiVersions: ["*"], resources: ["*"]}
  validations:
  - expression: "object.spec.replicas >="
`, "validations[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]string{write(t, map[string]string{"p.yaml": tc.file})})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNonPolicyYAMLIsIgnored(t *testing.T) {
	e := load(t, map[string]string{"values.yaml": "replicas: 3\nimage: {tag: x}\n", "cm.yml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n", "notes.txt": "hi"})
	if len(e.Policies) != 0 {
		t.Errorf("want no policies, got %d", len(e.Policies))
	}
}

const replicasTests = `
apiVersion: manifesto.io/v1
kind: PolicyTest
metadata: {name: min-replicas}
policy: min-replicas
cases:
- name: one replica
  expect: fail
  message: at least 2
  object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 1}}
- name: two replicas
  expect: pass
  object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 2}}
- name: wrong expectation, passes but expected to fail
  expect: fail
  object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 3}}
- name: wrong expectation, fails but expected to pass
  expect: pass
  object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 1}}
- name: wrong message
  expect: fail
  message: nonsense
  object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 1}}
- name: not matched by the policy
  expect: fail
  object: {apiVersion: v1, kind: ConfigMap, metadata: {name: web}}
`

func TestPolicyTests(t *testing.T) {
	dir := write(t, map[string]string{"policy.yaml": replicasPolicy, "policy_test.yaml": replicasTests})
	e, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	suites, err := LoadTests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range e.RunTests(context.Background(), suites) {
		status := "ok"
		if r.Err != nil {
			status = r.Err.Error()
		}
		got = append(got, r.Case+" => "+status)
	}
	want := []string{
		"one replica => ok",
		"two replicas => ok",
		"wrong expectation, passes but expected to fail => expected a finding, got none",
		"wrong expectation, fails but expected to pass => expected no findings, got: run at least 2 replicas",
		`wrong message => no finding contains "nonsense"`,
		"not matched by the policy => expected a finding, got none",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results: %v", len(got), got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("case %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

func TestPolicyTestForUnknownPolicy(t *testing.T) {
	dir := write(t, map[string]string{
		"policy.yaml": replicasPolicy,
		"t.yaml": `
apiVersion: manifesto.io/v1
kind: PolicyTest
policy: no-such-policy
cases: [{name: x, expect: pass, object: {kind: Deployment}}]
`})
	e, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	suites, err := LoadTests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	rs := e.RunTests(context.Background(), suites)
	if len(rs) != 1 || rs[0].Err == nil || !strings.Contains(rs[0].Err.Error(), `no policy named "no-such-policy"`) {
		t.Errorf("got %+v", rs)
	}
}

func TestMalformedPolicyTests(t *testing.T) {
	for name, body := range map[string]string{
		"no policy":  "apiVersion: manifesto.io/v1\nkind: PolicyTest\ncases: []\n",
		"bad expect": "apiVersion: manifesto.io/v1\nkind: PolicyTest\npolicy: p\ncases: [{name: x, expect: maybe, object: {a: b}}]\n",
		"no object":  "apiVersion: manifesto.io/v1\nkind: PolicyTest\npolicy: p\ncases: [{name: x, expect: pass}]\n",
	} {
		if _, err := LoadTests([]string{write(t, map[string]string{"t.yaml": body})}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
