// Package celpolicy runs Kubernetes ValidatingAdmissionPolicy files against
// rendered resources, so the policy a team enforces at admission is the same
// file checked at PR time.
//
// A policy file is a ValidatingAdmissionPolicy, optionally with
// ValidatingAdmissionPolicyBindings and the param objects they reference, all
// in ordinary YAML files under a policy directory. Differences from a cluster:
//
//   - A policy with no binding applies to every matching resource, as if it
//     had one Deny binding. A cluster ignores an unbound policy.
//   - `object` and `params` are dynamically typed, so an expression is not
//     type-checked against the resource schema. Expressions that compile in a
//     cluster compile here; some that a cluster rejects may not be caught.
//   - `authorizer` and `namespaceObject` are not available offline, and
//     `request` carries only operation (always CREATE), name and namespace.
//   - Objects are not defaulted. A cluster fills in defaults (a Deployment's
//     replicas, a Service's type) before admission runs, but a rendered chart
//     has only what its templates wrote, so reading an unset field is an
//     evaluation error. Guard it with has(), and treat "unset" as the default.
//   - namespaceSelector cannot be evaluated (no namespaces), so a binding that
//     sets one is a load error.
//
// Severity is not part of the VAP API. It comes from the
// manifesto.io/severity annotation (high|medium|low, default medium), and a
// policy whose bindings only Warn or Audit reports low unless the annotation
// says otherwise.
package celpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	SeverityAnnotation = "manifesto.io/severity"
	TitleAnnotation    = "manifesto.io/title"

	admissionGroup = "admissionregistration.k8s.io/"
)

type Policy struct {
	ID        string
	Title     string
	Severity  string
	Resources []string
	File      string

	spec       admissionv1.ValidatingAdmissionPolicySpec
	bindings   []binding
	matchConds []compiled
	vars       []compiled
	validation []validation
	failOpen   bool
	params     []map[string]any // every non-policy object in the policy dirs
}

type binding struct {
	spec admissionv1.ValidatingAdmissionPolicyBindingSpec
}

type compiled struct {
	name string
	expr string
	prog cel.Program
}

type validation struct {
	compiled
	message    string
	messageExp *compiled
}

type Violation struct {
	Policy   *Policy
	Severity string
	Message  string
}

type Engine struct {
	Policies []*Policy
}

func Load(dirs []string) (*Engine, error) {
	var (
		policies []*Policy
		bindings []binding
		others   []map[string]any
	)
	for _, dir := range dirs {
		err := walkDocs(dir, func(p string, doc map[string]any) error {
			apiVersion, _ := doc["apiVersion"].(string)
			kind, _ := doc["kind"].(string)
			switch {
			case strings.HasPrefix(apiVersion, admissionGroup) && kind == "ValidatingAdmissionPolicy":
				var vap admissionv1.ValidatingAdmissionPolicy
				if err := convert(doc, &vap); err != nil {
					return fmt.Errorf("%s: %w", p, err)
				}
				pol := &Policy{ID: vap.Name, spec: vap.Spec, File: p}
				pol.Title = vap.Annotations[TitleAnnotation]
				if pol.Title == "" {
					pol.Title = vap.Name
				}
				if s, ok := vap.Annotations[SeverityAnnotation]; ok {
					pol.Severity = strings.ToLower(s)
					if pol.Severity != "high" && pol.Severity != "medium" && pol.Severity != "low" {
						return fmt.Errorf("%s: %s: annotation %s is %q: want high, medium, or low", p, vap.Name, SeverityAnnotation, s)
					}
				}
				policies = append(policies, pol)
			case strings.HasPrefix(apiVersion, admissionGroup) && kind == "ValidatingAdmissionPolicyBinding":
				var vb admissionv1.ValidatingAdmissionPolicyBinding
				if err := convert(doc, &vb); err != nil {
					return fmt.Errorf("%s: %w", p, err)
				}
				if vb.Spec.MatchResources != nil && vb.Spec.MatchResources.NamespaceSelector != nil &&
					(len(vb.Spec.MatchResources.NamespaceSelector.MatchLabels) > 0 || len(vb.Spec.MatchResources.NamespaceSelector.MatchExpressions) > 0) {
					return fmt.Errorf("%s: binding %s sets namespaceSelector, which cannot be evaluated without a cluster", p, vb.Name)
				}
				bindings = append(bindings, binding{spec: vb.Spec})
			case apiVersion == testAPIVersion && kind == testKind:
				// Read by LoadTests, not a param object.
			default:
				others = append(others, doc)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("loading CEL policies from %s: %w", dir, err)
		}
	}

	byName := map[string]*Policy{}
	for _, p := range policies {
		if byName[p.ID] != nil {
			return nil, fmt.Errorf("%s: policy %q is defined twice (also in %s)", p.File, p.ID, byName[p.ID].File)
		}
		byName[p.ID] = p
	}
	for _, b := range bindings {
		p := byName[b.spec.PolicyName]
		if p == nil {
			return nil, fmt.Errorf("a ValidatingAdmissionPolicyBinding refers to policy %q, which is not in the policy directories", b.spec.PolicyName)
		}
		p.bindings = append(p.bindings, b)
	}

	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	e := &Engine{}
	for _, p := range policies {
		p.params = others
		if err := p.compile(env); err != nil {
			return nil, fmt.Errorf("%s: policy %s: %w", p.File, p.ID, err)
		}
		e.Policies = append(e.Policies, p)
	}
	sort.Slice(e.Policies, func(i, j int) bool { return e.Policies[i].ID < e.Policies[j].ID })
	return e, nil
}

func walkDocs(dir string, fn func(path string, doc map[string]any) error) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ext := strings.ToLower(filepath.Ext(p)); d.IsDir() || (ext != ".yaml" && ext != ".yml") {
			return nil
		}
		docs, err := readDocs(p)
		if err != nil {
			return err
		}
		for _, doc := range docs {
			if err := fn(p, doc); err != nil {
				return err
			}
		}
		return nil
	})
}

func readDocs(path string) ([]map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []map[string]any
	for {
		var raw any
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("%s: invalid YAML: %w", path, err)
		}
		if m, ok := raw.(map[string]any); ok {
			out = append(out, m)
		}
	}
}

// convert goes through JSON because the API types' field tags are JSON tags.
func convert(doc map[string]any, into any) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

func newEnv() (*cel.Env, error) {
	base, err := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()).Extend(environment.VersionedOptions{
		IntroducedVersion: version.MajorMinor(1, 0),
		EnvOptions: []cel.EnvOption{
			cel.Variable("object", cel.DynType),
			cel.Variable("oldObject", cel.DynType),
			cel.Variable("params", cel.DynType),
			cel.Variable("request", cel.DynType),
			cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}
	return base.Env(environment.StoredExpressions)
}

func (p *Policy) compile(env *cel.Env) error {
	if p.spec.MatchConstraints == nil || len(p.spec.MatchConstraints.ResourceRules) == 0 {
		return errors.New("spec.matchConstraints.resourceRules is required")
	}
	for _, r := range p.spec.MatchConstraints.ResourceRules {
		for _, res := range r.Resources {
			if !slices.Contains(p.Resources, res) {
				p.Resources = append(p.Resources, res)
			}
		}
	}
	p.failOpen = p.spec.FailurePolicy != nil && *p.spec.FailurePolicy == admissionv1.Ignore

	c := func(what, expr string) (compiled, error) {
		ast, iss := env.Compile(expr)
		if iss != nil && iss.Err() != nil {
			msg := iss.Err().Error()
			for _, unsupported := range []string{"authorizer", "namespaceObject"} {
				if strings.Contains(msg, "'"+unsupported+"'") {
					msg += fmt.Sprintf("\n(%s is not available when scanning without a cluster)", unsupported)
				}
			}
			return compiled{}, fmt.Errorf("%s: %s", what, msg)
		}
		prog, err := env.Program(ast, cel.InterruptCheckFrequency(100))
		if err != nil {
			return compiled{}, fmt.Errorf("%s: %w", what, err)
		}
		return compiled{name: what, expr: expr, prog: prog}, nil
	}

	for i, m := range p.spec.MatchConditions {
		cc, err := c(fmt.Sprintf("matchConditions[%d] %q", i, m.Name), m.Expression)
		if err != nil {
			return err
		}
		p.matchConds = append(p.matchConds, cc)
	}
	for i, v := range p.spec.Variables {
		cc, err := c(fmt.Sprintf("variables[%d] %q", i, v.Name), v.Expression)
		if err != nil {
			return err
		}
		cc.name = v.Name
		p.vars = append(p.vars, cc)
	}
	if len(p.spec.Validations) == 0 {
		return errors.New("spec.validations is empty")
	}
	for i, v := range p.spec.Validations {
		cc, err := c(fmt.Sprintf("validations[%d]", i), v.Expression)
		if err != nil {
			return err
		}
		val := validation{compiled: cc, message: v.Message}
		if v.MessageExpression != "" {
			me, err := c(fmt.Sprintf("validations[%d].messageExpression", i), v.MessageExpression)
			if err != nil {
				return err
			}
			val.messageExp = &me
		}
		p.validation = append(p.validation, val)
	}

	if p.Severity == "" {
		p.Severity = "medium"
		if len(p.bindings) > 0 && !slices.ContainsFunc(p.bindings, func(b binding) bool {
			return slices.Contains(b.spec.ValidationActions, admissionv1.Deny)
		}) {
			p.Severity = "low"
		}
	}
	return nil
}

func (e *Engine) Eval(ctx context.Context, obj map[string]any) ([]Violation, error) {
	var out []Violation
	object := toUnstructured(obj).(map[string]any)
	for _, p := range e.Policies {
		vs, err := p.eval(ctx, object)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.ID, err)
		}
		out = append(out, vs...)
	}
	return out, nil
}

func (p *Policy) eval(ctx context.Context, object map[string]any) ([]Violation, error) {
	if !matches(p.spec.MatchConstraints, object) {
		return nil, nil
	}
	bindings := p.bindings
	if len(bindings) == 0 {
		bindings = []binding{{}}
	}
	var out []Violation
	for _, b := range bindings {
		if b.spec.MatchResources != nil && !matches(b.spec.MatchResources, object) {
			continue
		}
		paramSets, missing, err := p.resolveParams(b, object)
		if err != nil {
			return nil, err
		}
		if missing != "" {
			out = append(out, Violation{Policy: p, Severity: p.Severity, Message: missing})
			continue
		}
		for _, params := range paramSets {
			vs, err := p.evalOne(ctx, object, params)
			if err != nil {
				return nil, err
			}
			out = append(out, vs...)
		}
	}
	return out, nil
}

func (p *Policy) evalOne(ctx context.Context, object, params map[string]any) ([]Violation, error) {
	meta, _ := object["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	ns, _ := meta["namespace"].(string)
	act := map[string]any{
		"object":    object,
		"oldObject": nil,
		"params":    nil,
		"request":   map[string]any{"operation": "CREATE", "name": name, "namespace": ns},
		"variables": map[string]any{},
	}
	if params != nil {
		act["params"] = params
	}

	fail := func(what string, err error) ([]Violation, error) {
		if p.failOpen {
			return nil, nil
		}
		msg := fmt.Sprintf("%s failed: %v", what, err)
		if strings.Contains(err.Error(), "no such key") {
			msg += " (the rendered object does not set it; guard with has())"
		}
		return []Violation{{Policy: p, Severity: p.Severity, Message: msg}}, nil
	}

	for _, m := range p.matchConds {
		v, _, err := m.prog.ContextEval(ctx, act)
		if err != nil {
			return fail(m.name, err)
		}
		if ok, _ := v.Value().(bool); !ok {
			return nil, nil
		}
	}

	vars := map[string]any{}
	act["variables"] = vars
	for _, v := range p.vars {
		val, _, err := v.prog.ContextEval(ctx, act)
		if err != nil {
			// Variables are lazy in a cluster: an error only matters if the
			// variable is used, and then it shows up as a missing key.
			continue
		}
		vars[v.name] = val
	}

	var out []Violation
	for _, v := range p.validation {
		res, _, err := v.prog.ContextEval(ctx, act)
		if err != nil {
			vs, _ := fail(v.name, err)
			out = append(out, vs...)
			continue
		}
		ok, isBool := res.Value().(bool)
		if !isBool {
			return nil, fmt.Errorf("%s must evaluate to a bool, got %s", v.name, res.Type().TypeName())
		}
		if ok {
			continue
		}
		out = append(out, Violation{Policy: p, Severity: p.Severity, Message: v.failure(ctx, act)})
	}
	return out, nil
}

func (v validation) failure(ctx context.Context, act map[string]any) string {
	if v.messageExp != nil {
		if r, _, err := v.messageExp.prog.ContextEval(ctx, act); err == nil {
			if s, ok := r.Value().(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	if v.message != "" {
		return v.message
	}
	return "failed expression: " + strings.TrimSpace(v.expr)
}

// missing is a finding message when a binding needs params that are not among
// the policy files.
func (p *Policy) resolveParams(b binding, object map[string]any) (sets []map[string]any, missing string, err error) {
	if p.spec.ParamKind == nil {
		return []map[string]any{nil}, "", nil
	}
	ref := b.spec.ParamRef
	if ref == nil {
		// A policy that declares paramKind but has no paramRef evaluates with
		// params unset.
		return []map[string]any{nil}, "", nil
	}
	var selector labels.Selector = labels.Everything()
	if ref.Selector != nil {
		if selector, err = metav1.LabelSelectorAsSelector(ref.Selector); err != nil {
			return nil, "", fmt.Errorf("paramRef.selector: %w", err)
		}
	}
	for _, d := range p.params {
		if d["apiVersion"] != p.spec.ParamKind.APIVersion || d["kind"] != p.spec.ParamKind.Kind {
			continue
		}
		md, _ := d["metadata"].(map[string]any)
		if ref.Name != "" && md["name"] != ref.Name {
			continue
		}
		if ref.Namespace != "" && md["namespace"] != ref.Namespace {
			continue
		}
		lbls := map[string]string{}
		if m, ok := md["labels"].(map[string]any); ok {
			for k, v := range m {
				lbls[k], _ = v.(string)
			}
		}
		if !selector.Matches(labels.Set(lbls)) {
			continue
		}
		sets = append(sets, toUnstructured(d).(map[string]any))
	}
	if len(sets) == 0 {
		if ref.ParameterNotFoundAction != nil && *ref.ParameterNotFoundAction == admissionv1.AllowAction {
			return nil, "", nil
		}
		return nil, fmt.Sprintf("no %s params found for the binding (paramRef %s)", p.spec.ParamKind.Kind, describeRef(ref)), nil
	}
	return sets, "", nil
}

func describeRef(r *admissionv1.ParamRef) string {
	if r.Name != "" {
		return "name " + r.Name
	}
	return "selector"
}

// Subresource rules never match a rendered object.
func matches(m *admissionv1.MatchResources, obj map[string]any) bool {
	if m == nil {
		return false
	}
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	group, ver := "", apiVersion
	if g, v, ok := strings.Cut(apiVersion, "/"); ok {
		group, ver = g, v
	}
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	res := pluralize(kind)

	hit := func(rules []admissionv1.NamedRuleWithOperations) bool {
		for _, r := range rules {
			if !inList(r.APIGroups, group) || !inList(r.APIVersions, ver) {
				continue
			}
			if !slices.ContainsFunc(r.Resources, func(s string) bool { return s == "*" || s == res }) {
				continue
			}
			if len(r.ResourceNames) > 0 && !slices.Contains(r.ResourceNames, name) {
				continue
			}
			return true
		}
		return false
	}
	if !hit(m.ResourceRules) || hit(m.ExcludeResourceRules) {
		return false
	}
	if sel := m.ObjectSelector; sel != nil {
		s, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return false
		}
		lbls := map[string]string{}
		if l, ok := meta["labels"].(map[string]any); ok {
			for k, v := range l {
				lbls[k], _ = v.(string)
			}
		}
		return s.Matches(labels.Set(lbls))
	}
	return true
}

func inList(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return x == "*" || x == s })
}

// Rendered objects carry no discovery data, so this covers the regular
// plurals Kubernetes uses (Ingress -> ingresses, NetworkPolicy ->
// networkpolicies), plus Endpoints.
func pluralize(kind string) string {
	k := strings.ToLower(kind)
	switch {
	case k == "endpoints":
		return k
	case strings.HasSuffix(k, "s") || strings.HasSuffix(k, "x"):
		return k + "es"
	case strings.HasSuffix(k, "y") && len(k) > 1 && !strings.ContainsRune("aeiou", rune(k[len(k)-2])):
		return k[:len(k)-1] + "ies"
	}
	return k + "s"
}

// Whole-number floats become int64, as in Kubernetes' unstructured decoding,
// so `object.spec.replicas == 2` compares int to int.
func toUnstructured(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = toUnstructured(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = toUnstructured(x)
		}
		return out
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
	}
	return v
}
