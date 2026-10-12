# AGENTS.md

Operational notes for agents working in this repo. Humans: see README.md and DESIGN.md for the full explainer.

## Build, test, validate

```sh
make              # fmt-check, vet, test, build -> bin/manifesto
make build        # go build -> bin/manifesto
make test         # go test ./...
make vet          # go vet ./...
make fmt          # gofmt -w .
make fmt-check    # fails if gofmt would change anything
golangci-lint run # lint, matches CI (.github/workflows/ci.yml); no Makefile target yet
```

Run `make` (or at minimum `fmt-check`, `vet`, `test`) plus `golangci-lint run` before considering any change done. `gofmt` and `golangci-lint` are enforced in CI, not optional.

## Layout

- `cmd/manifesto` — CLI entrypoint
- `internal/manifest` — chart/manifest loading and Helm rendering
- `internal/policy` — policy engine (Rego + CEL/ValidatingAdmissionPolicy)
- `internal/policy/builtin` — built-in `k8s.*` Rego policies shipped with manifesto
- `internal/pss` — Pod Security Standards checks (wraps upstream `pod-security-admission`)
- `internal/tmpllint` — raw template source checks (`tmpl.*`), before rendering
- `internal/celpolicy` — CEL-based ValidatingAdmissionPolicy support
- `internal/ignore` — `manifesto.io/ignore` annotation, ignore file, `manifesto:ignore` comments
- `internal/report` — output formatting (text, JSON, SARIF, GitHub annotations)
- `internal/severity` — severity levels shared across policy types
- `internal/scaffold` — `manifesto new` policy scaffolding
- `action.yml` — GitHub Action wrapper around the CLI
- `examples/policies/`, `testdata/charts/` — sample policies and chart fixtures used by tests, not real policies; don't "fix" them without reason

## Conventions

- Small, atomic diffs. One concern per change. Never mix formatting and logic changes.
- Comments only for WHY, never what the code does.
- For bug fixes: add a failing test first (each internal package has a sibling `_test.go`), then fix.
- Before changing behavior around policy evaluation, PSS, template linting, or ignore handling: identify root cause with concrete evidence (a failing policy example, a scan output, a test), not just a symptom.
- Changes to `internal/policy/builtin` need corresponding `*_test.rego` coverage (and a `PolicyTest` fixture for CEL/ValidatingAdmissionPolicy changes).
- Releases are tagged, not automatic on merge — don't assume a merge to main publishes a release (see `.goreleaser.yaml`, `.github/workflows/release.yml`).
- Never install extra dependencies unless explicitly asked.
