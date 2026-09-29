package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deployment(podSpec map[string]any) map[string]any {
	return map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "web"},
		"spec":     map[string]any{"template": map[string]any{"spec": withAccount(podSpec)}},
	}
}

// withAccount gives a pod spec a dedicated ServiceAccount, unless the case
// sets one, so cases don't trip k8s.default_service_account by accident.
func withAccount(podSpec map[string]any) map[string]any {
	if _, ok := podSpec["serviceAccountName"]; !ok {
		podSpec["serviceAccountName"] = "web"
	}
	return podSpec
}

// compliant is a container that passes every built-in rule, so each case
// below only has to break the one thing it's testing.
func compliant(overrides map[string]any) map[string]any {
	c := map[string]any{
		"name":            "app",
		"image":           "ghcr.io/acme/app:1.2.3",
		"securityContext": map[string]any{"runAsNonRoot": true, "readOnlyRootFilesystem": true},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": "100m"},
			"limits":   map[string]any{"memory": "128Mi"},
		},
		"livenessProbe":  map[string]any{},
		"readinessProbe": map[string]any{},
	}
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func evalIDs(t *testing.T, obj map[string]any) []string {
	t.Helper()
	e, err := Load(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := e.Eval(context.Background(), obj["kind"].(string), obj)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range vs {
		ids = append(ids, v.Policy.ID)
	}
	return ids
}

func TestBuiltins(t *testing.T) {
	cases := []struct {
		name string
		obj  map[string]any
		want []string
	}{
		{"compliant", deployment(map[string]any{"containers": []any{compliant(nil)}}), nil},
		{"latest tag", deployment(map[string]any{"containers": []any{compliant(map[string]any{"image": "nginx:latest"})}}), []string{"k8s.image_tag"}},
		{"no tag", deployment(map[string]any{"containers": []any{compliant(map[string]any{"image": "nginx"})}}), []string{"k8s.image_tag"}},
		{"empty tag", deployment(map[string]any{"containers": []any{compliant(map[string]any{"image": "nginx:"})}}), []string{"k8s.image_tag"}},
		{"registry port is not a tag", deployment(map[string]any{"containers": []any{compliant(map[string]any{"image": "localhost:5000/app"})}}), []string{"k8s.image_tag"}},
		{"digest", deployment(map[string]any{"containers": []any{compliant(map[string]any{"image": "nginx@sha256:abc"})}}), nil},
		{"no memory limit", deployment(map[string]any{"containers": []any{compliant(map[string]any{"resources": map[string]any{"requests": map[string]any{"cpu": "1"}}})}}), []string{"k8s.resources"}},
		{"cpu limit implies request", deployment(map[string]any{"containers": []any{compliant(map[string]any{"resources": map[string]any{"limits": map[string]any{"cpu": "1", "memory": "1Gi"}}})}}), nil},
		{"no probes", deployment(map[string]any{"containers": []any{compliant(map[string]any{"livenessProbe": nil})}}), []string{"k8s.probes"}},
		{"job exempt from probes", map[string]any{
			"kind": "Job", "metadata": map[string]any{"name": "j"},
			"spec": map[string]any{"template": map[string]any{"spec": withAccount(map[string]any{"containers": []any{compliant(map[string]any{"livenessProbe": nil, "readinessProbe": nil})}})}},
		}, nil},
		{"cronjob pod spec is found", map[string]any{
			"kind": "CronJob", "metadata": map[string]any{"name": "c"},
			"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": withAccount(map[string]any{"containers": []any{compliant(map[string]any{"image": "busybox"})}})}}}},
		}, []string{"k8s.image_tag"}},
		{"not a workload", map[string]any{"kind": "ConfigMap", "metadata": map[string]any{"name": "cm"}}, nil},

		{"default service account, unset", deployment(map[string]any{"serviceAccountName": nil, "containers": []any{compliant(nil)}}), []string{"k8s.default_service_account"}},
		{"default service account, named", deployment(map[string]any{"serviceAccountName": "default", "containers": []any{compliant(nil)}}), []string{"k8s.default_service_account"}},
		{"deprecated serviceAccount field", deployment(map[string]any{"serviceAccountName": nil, "serviceAccount": "web", "containers": []any{compliant(nil)}}), nil},

		{"writable root filesystem", deployment(map[string]any{"containers": []any{compliant(map[string]any{"securityContext": map[string]any{"runAsNonRoot": true}})}}), []string{"k8s.readonly_rootfs"}},
		{"readOnlyRootFilesystem false", deployment(map[string]any{"containers": []any{compliant(map[string]any{"securityContext": map[string]any{"readOnlyRootFilesystem": false}})}}), []string{"k8s.readonly_rootfs"}},

		{"literal password", deployment(map[string]any{"containers": []any{compliant(map[string]any{"env": []any{map[string]any{"name": "DB_PASSWORD", "value": "hunter2"}}})}}), []string{"k8s.secret_env_literal"}},
		{"api key spelled two ways", deployment(map[string]any{"containers": []any{compliant(map[string]any{"env": []any{
			map[string]any{"name": "STRIPE_API_KEY", "value": "sk_live_x"}, map[string]any{"name": "service-token", "value": "abc"}}})}}), []string{"k8s.secret_env_literal", "k8s.secret_env_literal"}},
		{"password from a secret", deployment(map[string]any{"containers": []any{compliant(map[string]any{"env": []any{map[string]any{"name": "DB_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db", "key": "pw"}}}}})}}), nil},
		{"credential-named var that is not a credential", deployment(map[string]any{"containers": []any{compliant(map[string]any{"env": []any{
			map[string]any{"name": "DB_PASSWORD_FILE", "value": "/run/secrets/pw"},
			map[string]any{"name": "TOKEN_SECRET_NAME", "value": "tokens"},
			map[string]any{"name": "ENABLE_TOKEN_AUTH", "value": "true"},
			map[string]any{"name": "TOKEN_TTL", "value": "3600"},
			map[string]any{"name": "SECRET_KEY", "value": ""},
			map[string]any{"name": "ALLOW_EMPTY_PASSWORD", "value": "no"},
			map[string]any{"name": "SECRETS", "value": "/run/secrets/additional"},
			map[string]any{"name": "LOG_LEVEL", "value": "debug"}}})}}), nil},

		{"ingress without tls", map[string]any{"kind": "Ingress", "metadata": map[string]any{"name": "i"}, "spec": map[string]any{}}, []string{"k8s.ingress_tls"}},
		{"ingress with empty tls list", map[string]any{"kind": "Ingress", "metadata": map[string]any{"name": "i"}, "spec": map[string]any{"tls": []any{}}}, []string{"k8s.ingress_tls"}},
		{"ingress with tls", map[string]any{"kind": "Ingress", "metadata": map[string]any{"name": "i"}, "spec": map[string]any{"tls": []any{map[string]any{"secretName": "x"}}}}, nil},
		{"alb ingress with an ACM certificate", map[string]any{"kind": "Ingress", "metadata": map[string]any{"name": "i", "annotations": map[string]any{"alb.ingress.kubernetes.io/certificate-arn": "arn:aws:acm:x"}}, "spec": map[string]any{}}, nil},

		{"wildcard verbs", map[string]any{"kind": "ClusterRole", "metadata": map[string]any{"name": "r"}, "rules": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"*"}}}}, []string{"k8s.rbac_wildcard"}},
		{"wildcard resources and verbs", map[string]any{"kind": "Role", "metadata": map[string]any{"name": "r"}, "rules": []any{map[string]any{"resources": []any{"*"}, "verbs": []any{"*"}}}}, []string{"k8s.rbac_wildcard", "k8s.rbac_wildcard"}},
		{"specific rules", map[string]any{"kind": "Role", "metadata": map[string]any{"name": "r"}, "rules": []any{map[string]any{"resources": []any{"pods"}, "verbs": []any{"get", "list"}}}}, nil},
		{"cluster-admin binding", map[string]any{"kind": "ClusterRoleBinding", "metadata": map[string]any{"name": "b"}, "roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}}, []string{"k8s.rbac_wildcard"}},
		{"ordinary binding", map[string]any{"kind": "RoleBinding", "metadata": map[string]any{"name": "b"}, "roleRef": map[string]any{"kind": "Role", "name": "reader"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(evalIDs(t, tc.obj), ",")
			want := strings.Join(tc.want, ",")
			if got != want {
				t.Errorf("got [%s], want [%s]", got, want)
			}
		})
	}
}

func writePolicy(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUserPolicyContract(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "team.rego", `# METADATA
# title: team label
# custom:
#   severity: low
#   kinds: [Service]
package manifesto.team

deny contains "no team" if not input.metadata.labels.team

warn contains {"msg": "single port", "path": "spec.ports", "severity": "medium"} if count(input.spec.ports) == 1
`)
	// Pre-1.0 syntax, as most Conftest policies are written.
	writePolicy(t, dir, "legacy.rego", `package main
deny[msg] { input.kind == "Service"; msg := "legacy" }
`)
	writePolicy(t, dir, "typo.rego", "package typo\ndenny contains 1 if true\n")

	e, err := Load(context.Background(), Options{Dirs: []string{dir}, NoBuiltins: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Warnings) != 1 || !strings.Contains(e.Warnings[0], "typo") {
		t.Errorf("want one warning about package typo, got %v", e.Warnings)
	}

	svc := map[string]any{"kind": "Service", "metadata": map[string]any{"name": "s"}, "spec": map[string]any{"ports": []any{80}}}
	vs, err := e.Eval(context.Background(), "Service", svc)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range vs {
		got = append(got, v.Policy.ID+"|"+v.Severity+"|"+v.Message+"|"+v.Path)
	}
	want := "main|high|legacy|,team|low|no team|,team|medium|single port|spec.ports"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v\nwant %s", got, want)
	}

	vs, err = e.Eval(context.Background(), "Deployment", map[string]any{"kind": "Deployment", "metadata": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Errorf("custom.kinds should keep team off a Deployment, got %v", vs)
	}
}

func TestCrossResourceData(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "pdb.rego", `package pdb
deny contains "no PodDisruptionBudget" if {
	input.kind == "Deployment"
	not any_pdb
}
any_pdb if data.chart.resources[_].kind == "PodDisruptionBudget"
`)
	dep := map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "d"}}
	for _, tc := range []struct {
		resources []map[string]any
		want      int
	}{
		{[]map[string]any{dep}, 1},
		{[]map[string]any{dep, {"kind": "PodDisruptionBudget"}}, 0},
	} {
		e, err := Load(context.Background(), Options{Dirs: []string{dir}, NoBuiltins: true, Resources: tc.resources})
		if err != nil {
			t.Fatal(err)
		}
		vs, err := e.Eval(context.Background(), "Deployment", dep)
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != tc.want {
			t.Errorf("with %d resources: got %d findings, want %d", len(tc.resources), len(vs), tc.want)
		}
	}
}

func TestBadSeverityIsAnError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.rego", "# METADATA\n# custom:\n#   severity: hihg\npackage p\ndeny contains \"x\" if true\n")
	_, err := Load(context.Background(), Options{Dirs: []string{dir}})
	if err == nil || !strings.Contains(err.Error(), "hihg") {
		t.Fatalf("want an error naming the bad severity, got %v", err)
	}
}
