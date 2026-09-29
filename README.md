# manifesto

A **fast**, ergonomic policy scanner for Helm charts and Kubernetes manifests: checks the rendered output and the raw template source, with built-in best practices and Pod Security Standards, and your own policies in [Rego](https://www.openpolicyagent.org/docs/policy-language) or as [CEL](https://kubernetes.io/docs/reference/using-api/cel/)-based `ValidatingAdmissionPolicy`

## Why 

Off the shelf tools already cover much of what manifesto does, but each comes with a tradeoff: some are slow to run, some use their own policy language, so your policies and tests aren't portable, most accept only one type of policy, and few look at the raw template source at all.

`manifesto` puts these in one entry point: fast runs, custom policies in Rego or CEL with unit tests for both, a check of the raw templates as well as the rendered output, and SARIF and GitHub Actions annotations built in.

## Quick start

```sh
make build 
bin/manifesto scan testdata/charts/bad 
```

```
testdata/charts/bad/templates/deployment.yaml
  medium  tmpl.hardcoded_namespace       line 5: namespace "payments" is hardcoded: use {{ .Release.Namespace }} so `helm install -n` works
  medium  tmpl.hardcoded_image           line 24: image "envoyproxy/envoy:latest" is hardcoded: template it from values so users can override registry and tag
  Deployment/release-name-api -n payments
    high    k8s.image_tag                  container "api" uses "ghcr.io/acme/api:" with an empty tag: is the tag value unset?
    high    k8s.image_tag                  container "proxy" uses "envoyproxy/envoy:latest": pin a version or digest instead of :latest
    high    pss.hostNamespaces             host namespaces: hostNetwork=true
    high    pss.privileged                 privileged: container "proxy" must not set securityContext.privileged=true
    …
✗ 26 findings (5 high, 18 medium, 3 low)  2 resources · 24 policies · 1 ignored · 20ms
```

## Your first policy

```sh
manifesto new require-team-label --kind Deployment,StatefulSet
manifesto test # the generated test passes
manifesto scan /path/to/chart # findings show up as "require_team_label"
```

`new` writes `.manifesto/policies/require_team_label.rego`, which `scan`
and `test` pick up automatically:

```rego
# METADATA
# title: require team label
# custom:
#   severity: medium
#   kinds: [Deployment, StatefulSet]
package require_team_label

import data.manifesto.lib

deny contains msg if {
	not lib.has_label("team")
	msg := sprintf("%s has no \"team\" label", [lib.name])
}
```


### Sourcing custom policies

`manifesto` has no mechanism for fetching custom policies. It reads `.manifesto/policies/` (or any path with `-p`). Your custom policies need to be copied into the workspace before it scans:

```sh
# copy custom policies to .manifesto in the workspace
cp -r ../my-policies/policies .manifesto/policies    # or git clone, an artifact download, ...
manifesto scan ./chart -f values/prod.yaml
```

### Example: policies for your own conventions

The built-in checks, while aiming to satisfy common best practices, are generic. The value comes from encoding what *your* organization requires, including for CRDs a generic scanner has never heard of.
The Rego examples in [examples/policies/](examples/policies/) (run `manifesto test -p examples/policies`):

| File | Enforces |
|---|---|
| `prometheusrule_runbook.rego` | every `PrometheusRule` alert must have `annotations.runbook_url` (recording rules are exempt) |
| `ingress_alb_ssl_policy.rego` | every AWS Load Balancer Controller `Ingress` must set `alb.ingress.kubernetes.io/ssl-policy` to the approved value; other ingress controllers are skipped |
| `externalsecret_store.rego` | an `ExternalSecret` can only read from an approved `ClusterSecretStore` |
| `argocd_application.rego` | an Argo CD `Application` must not be in the `default` project and must pin a `targetRevision` |
| `required_labels.rego` | workloads have the organization's required set of labels |
| `pdb_required.rego` | a cross-resource check: replicated Deployments have a `PodDisruptionBudget` |

```
Ingress/web
  high  ingress_alb_ssl_policy  Ingress/web is missing the alb.ingress.kubernetes.io/ssl-policy annotation (want "ELBSecurityPolicy-TLS-1-1-2017-01")
PrometheusRule/app
  high  prometheusrule_runbook  alert "HighErrorRate" in group "app" has no annotations.runbook_url (spec.groups[0].rules[1])
```

### ValidatingAdmissionPolicy

A `.yaml` file in a policy directory that holds a `ValidatingAdmissionPolicy` is loaded next to your Rego, so the same admission policies can be tested in CI 

See [examples/policies/](examples/policies/) (`min_replicas.yaml`, `no_hostpath.yaml`, and `image_registry.yaml`).

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: min-replicas
  annotations:
    manifesto.io/severity: medium          # high | medium (default) | low
spec:
  matchConstraints:
    resourceRules:
      - {apiGroups: ["apps"], apiVersions: ["v1"], resources: ["deployments"]}
  validations:
    - expression: "has(object.spec.replicas) && object.spec.replicas >= 2"
      message: "run at least 2 replicas"
```

Test a `ValidatingAdmissionPolicy` with a `PolicyTest` file next to it. Sample objects, and the outcome each should get. `manifesto test` runs these together with the Rego tests.

  ```yaml
  apiVersion: manifesto.io/v1
  kind: PolicyTest
  policy: min-replicas            # the ValidatingAdmissionPolicy's name
  cases:
    - name: one replica is flagged
      expect: fail                # pass | fail
      message: at least 2         # optional: a substring of the finding
      object: {apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 1}}
  ```

`expect: pass` means the policy reports nothing for the object. See `examples/policies/*_test.yaml`.

## What's checked

`manifesto policies` lists everything a scan runs.

**Pod Security Standards** (`pss.*`). These run the upstream checks from
[`k8s.io/pod-security-admission`](https://github.com/kubernetes/pod-security-admission),
the same code the API server's PodSecurity admission plugin uses. A chart that
passes here is admitted to a namespace labeled
`pod-security.kubernetes.io/enforce: <level>`. `--pss restricted` (default),
`baseline`, or `off`. Baseline violations are `high`; restricted-only
hardening is `medium`. Check IDs match upstream (`pss.privileged`,
`pss.hostNamespaces`, `pss.runAsNonRoot`, …), so they cross-reference the
[PSS docs](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

**Built-in Rego** (`k8s.*`). These are the checks PSS doesn't cover. Read them in
[internal/policy/builtin/](internal/policy/builtin/):

| ID | Severity | Checks |
|---|---|---|
| `k8s.image_tag` | high | `:latest`, no tag, or an empty tag (`repo:` from an unset value) |
| `k8s.resources` | medium | memory limit and CPU request. A CPU *limit* isn't required; the file explains why |
| `k8s.probes` | medium | liveness and readiness probes on Deployments, StatefulSets, and DaemonSets |
| `k8s.rbac_wildcard` | high | a `*` in a Role or ClusterRole's verbs or resources, or a binding to `cluster-admin` |
| `k8s.default_service_account` | medium | a pod that names no `serviceAccountName`, so runs as `default` |
| `k8s.secret_env_literal` | medium | an env var named like a password, token or key with an inline `value`. It is a heuristic on the name: `*_FILE`, `*_PATH`, `*_NAME` and `*_REF` names, and flag, number or path values, are skipped |
| `k8s.readonly_rootfs` | low | `securityContext.readOnlyRootFilesystem: true`, which the Pod Security Standards do not require even at `restricted` |
| `k8s.ingress_tls` | medium | an Ingress with no `spec.tls`, unless an ACM (ALB) or GKE certificate annotation supplies the certificate |

**Template source** (`tmpl.*`). These check the chart before rendering, with real
template line numbers. Each template is parsed with `text/template/parse`,
so only values that are literal from start to end are flagged. Comments
and templated values are never flagged.

| ID | Severity | Checks |
|---|---|---|
| `tmpl.hardcoded_image` | medium | `image:` with a literal value |
| `tmpl.hardcoded_namespace` | medium | `namespace:` with a literal value (breaks `helm install -n`) |

## Scanning

```sh
manifesto scan ./chart -f values/prod.yaml --set image.tag=1.2.3
manifesto scan ./chart -n payments --kube-version 1.31 -a monitoring.coreos.com/v1
manifesto scan rendered/                     # a manifest file or directory: real file:line
helm template ./chart | manifesto scan -     # stdin keeps "# Source:" attribution
```

Charts render in-process with the Helm v4 template engine, following the same
steps as `helm template`: default capabilities, dependency processing, values
schema validation, and hooks included except test hooks (`--include-tests`
adds them). Missing dependencies fail with a pointer to
`helm dependency build`. `-f` takes local files (or `-` for stdin), not URLs.

## Ignoring findings

Pick the mechanism by who is scanning and what the finding is about:

| You want to ignore | Use |
|---|---|
| a policy everywhere, for one run | `--ignore ID[,ID]` |
| a finding on one resource, and you can edit the manifest or chart | the `manifesto.io/ignore` annotation |
| a finding in a chart you don't own | the ignore file |
| a `tmpl.*` finding, and you own the chart | a `manifesto:ignore` comment in the template |

An ignored finding is not shown and does not affect the exit code. The
summary's "N ignored" counts every ignored finding, whichever way it was
ignored.

**Per run.** `--ignore k8s.probes,pss.seccompProfile_restricted`.

**On a resource: the annotation.** Set it on the resource's own `metadata`, not
on the pod template, and list the policy IDs, or `all`:

```yaml
metadata:
  name: migrate
  annotations:
    manifesto.io/ignore: "k8s.probes, k8s.resources"
```

It works the same for a manifest file and for a chart. Helm renders the
annotation into the output, so in a chart it goes in the template, next to the
resource it concerns.

**In a chart you don't own: the ignore file.** You cannot add an annotation to a
chart you pull from someone else, and a `--ignore` would hide the policy on every
resource. Put the exception in the repository that scans the chart, as
`.manifesto/ignore.yaml` (or `--ignore-file path`), and review it like code:

```yaml
ignore:
  - policy: pss.hostNamespaces
    resource: DaemonSet/*-node-exporter
    reason: a node exporter needs the host network by design
  - policy: k8s.*
    file: templates/jobs/*.yaml
    reason: throwaway migration jobs
```

- `policy` and `reason` are required. `reason` is there so the next reader knows
  why. The other fields, `resource` (`Kind/name`), `file` and `namespace`,
  narrow the match, and an entry matches only when every field it sets does.
- Every value is a glob where `*` matches any characters, so `policy: pss.*`
  works.
- `file` matches the whole path or any tail of it, so `templates/x.yaml` works
  however you named the chart on the command line.
- An entry that matched nothing prints a warning, so a rule that outlives the
  problem it was written for does not sit there unnoticed.

**In template source: a comment.** `tmpl.*` findings point at a line of the
template, not at a rendered resource, so an annotation cannot reach them. If you
own the chart, put a comment on the line, or on the line above it:

```yaml
namespace: kube-system {{/* manifesto:ignore tmpl.hardcoded_namespace */}}
```

or, for several checks at once, `{{/* manifesto:ignore tmpl.hardcoded_image, tmpl.hardcoded_namespace */}}`
(`all` works too). If you don't own the chart, use the ignore file with a `file`
pattern instead.

## CI

| `-o` value | Output |
|---|---|
| `text` | default, grouped by file then resource |
| `json` | findings and summary |
| `github` | GitHub Actions annotations on the PR diff |
| `sarif` | SARIF 2.1.0 for GitHub code scanning (`github/codeql-action/upload-sarif`) |

`-o` is repeatable, and each value can be `format=file`, so one scan feeds both
a human-readable log and a machine-readable report:

```sh
manifesto scan ./chart -o text -o sarif=manifesto.sarif
```

A GitHub Actions job that fails on findings, shows them in the log, and stores
them in code scanning. `if: always()` makes the upload run when the scan step
fails:

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Fetch custom policies 
    run: cp -r ../platform-policies/policies .manifesto/policies
  - run: manifesto scan ./chart -f values/prod.yaml -o text -o sarif=manifesto.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: manifesto.sarif }
```