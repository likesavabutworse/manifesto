# Design

## What manifesto is intended to be:

- **An engine, not a ruleset.** manifesto ships a small set of
built-in checks. Common sense defaults already widely followed,
plus PSS and the tools to author, test, and distribute
*your own* policies cheaply in Rego or CEL. Locally or from an OCI
registry. It does not try to be a comprehensive, pre-populated policy
library. 

- **In-process Helm rendering.** No `helm` deopendency, shelling out, or piping
`helm template` into another tool. One static binary renders the chart the
same way `helm template` does and scans the result. This is done entirely for speed
and convenience. 

- **Rego and CEL as equal, first class citizens.** Most tools pick one.
manifesto treats custom Rego and `ValidatingAdmissionPolicy`/CEL as
first-class, side by side, each with its own unit-testing path. The CEL path exists
specifically so a `ValidatingAdmissionPolicy` can be the _same file_ tested
in CI and applied to the cluster later.

- **First class support for raw template source scan.**
Rendering can mask problems (a hardcoded namespace that happens to match the
default release namespace in dev still renders "correctly"). `tmpllint`
checks the template text before Helm ever touches it, which is a cheap pass
most config scanners skip entirely because they only ever see rendered
YAML.

## No policy library

Most "library of generic Kubernetes Rego policies" projects are either archived 
or abandoned. The few that aren't are are overly generic and overzealous, which
only raises the barrier of entry instead of lowering it. See Checkov.

There isn't a credible _"here's ~20 maintained rules, just add `-p`"_ source to
point at today. So `manifesto` ingtentionally tries to stay neutral and only carry
a tiny set of built ins that is trivial to disable, but makes sourcing policies 
trivial, so users can pass any set of public, private or a combination of lists.

## No baseline (ratchet mode)

Baseline files solve a real problem for tools that ship broad, opinionated
rulesets by default: Checkov, kube-linter, ESLint and similar tools dump hundreds 
of findings on first run against an existing codebase, and a baseline is the only 
way to adopt them without a cleanup pass beforehand.

manifesto doesn't have that problem for two reasons:

1. The built-in set is deliberately slim and generic (one exception is
 `--pss restricted` as the default. But the flag is there for exactly 
 that reason and can be adjusted).
2. New org-specific policies (which will hit the same "wall of findings on
   an existing codebase" problem) already have a graduated rollout path built 
   into the engine itself: ship a new rule as `warn` (non-blocking at any sane 
   `--fail-on` threshold), watch it run across the fleet, fix or exempt,
   then flip it to `deny`. That's rollout via policy-authoring discipline,
   which fits better than mass suppression files.


## OCI bundles are Rego-only

**Designing for the Fat of the Curve**. Most organizational standards are far
more likely to be expressed as a Rego policy (see [examples/policies/](examples/policies/)),
so adding first class support for OPA's [native bundles](https://www.openpolicyagent.org/docs/management-bundles) and the security
features that come with it for free is there as a QoL imporvement. The `-p` flag
is repeatable, so CEL policies can still be included in the same run.


## Bundle signing and digest pinning

Both solve different problems:

- **Signing solves integrity**: is this the bundle the signer actually
  produced. That's manifesto's problem to solve, since nothing else in
  the pull path checks it. Provenance validation of a downloaded artifact
  fills a genuine a supply-chain gap.

- **Pinning solves reproducibility**: does `oci://repo:tag` resolve to the
  same content run over run. That's a registry/repository-policy problem
  (immutable tags, protected tags), not manifesto's to re-solve. If tag
  mutability is a concern for a given registry, the fix belongs at the
  registry or org level, where it's already a solved, standard feature.
  Coincidently, manifeasto can be used to enforce tag immutability when 
  creating a repository.

