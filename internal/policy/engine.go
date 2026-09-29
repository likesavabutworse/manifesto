// Package policy loads Rego policies (the embedded built-ins plus any user
// directories) and evaluates them against one rendered resource at a time.
//
// Authoring contract, kept deliberately close to Conftest's so existing
// policies carry over:
//
//   - Any package that defines a `deny` or `warn` rule is a policy. Its ID is
//     the package path, minus a leading "manifesto.".
//   - `input` is one rendered Kubernetes resource. All rendered resources are
//     also available as `data.chart.resources`, for cross-resource checks.
//   - Each `deny`/`warn` element is a message string, or an object with
//     "msg" and optional "path" and "severity".
//   - A package-level METADATA block sets title, description, and
//     custom.severity (high|medium|low, default high for deny) and
//     custom.kinds (only evaluate against these kinds).
//   - `warn` findings default to low severity.
package policy

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
)

//go:embed builtin/*.rego
var builtinFS embed.FS

const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Rank orders severities; lower is more severe. Unknown severities rank -1.
func Rank(s string) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	}
	return -1
}

type Policy struct {
	ID       string
	Title    string
	Severity string
	Kinds    []string
	File     string
	Builtin  bool

	hasDeny, hasWarn bool
	query            rego.PreparedEvalQuery
}

type Violation struct {
	Policy   *Policy
	Severity string
	Message  string
	Path     string
}

type Options struct {
	Dirs       []string
	NoBuiltins bool
	Resources  []map[string]any
	Print      io.Writer
}

type Engine struct {
	Policies []*Policy
	// Warnings are non-fatal load problems, e.g. a user package with no deny or
	// warn rule (usually a typo).
	Warnings []string
}

// LoadModules parses every built-in and user .rego file. Exposed for the
// test runner, which needs the same module set the scanner sees.
func LoadModules(dirs []string, noBuiltins bool) (map[string]*ast.Module, map[string]bool, error) {
	modules := map[string]*ast.Module{}
	builtin := map[string]bool{}

	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		name := "builtin/" + e.Name()
		// The helper library is always loaded: user policies import it
		// even when the built-in rules are switched off.
		if noBuiltins && e.Name() != "lib.rego" {
			continue
		}
		b, err := builtinFS.ReadFile(name)
		if err != nil {
			return nil, nil, err
		}
		m, err := parse(name, string(b))
		if err != nil {
			return nil, nil, err
		}
		modules[name] = m
		builtin[name] = true
	}

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(p) != ".rego" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			m, err := parse(p, string(b))
			if err != nil {
				return err
			}
			modules[p] = m
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("loading policies from %s: %w", dir, err)
		}
	}
	return modules, builtin, nil
}

// parse accepts both Rego v1 and the pre-1.0 syntax most Conftest policies
// in the wild are still written in; OPA compiles mixed-version modules
// together.
func parse(name, src string) (*ast.Module, error) {
	m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV1})
	if err == nil {
		return m, nil
	}
	if m0, err0 := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV0}); err0 == nil {
		return m0, nil
	}
	return nil, err
}

func Load(ctx context.Context, opts Options) (*Engine, error) {
	modules, builtin, err := LoadModules(opts.Dirs, opts.NoBuiltins)
	if err != nil {
		return nil, err
	}

	compiler := ast.NewCompiler().WithEnablePrintStatements(true)
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("compiling policies:\n%s", formatErrors(compiler.Errors))
	}

	resources := make([]any, len(opts.Resources))
	for i, r := range opts.Resources {
		resources[i] = r
	}
	store := inmem.NewFromObject(map[string]any{"chart": map[string]any{"resources": resources}})

	printer := opts.Print
	if printer == nil {
		printer = io.Discard
	}

	e := &Engine{}
	byPkg := map[string]*Policy{}
	var names []string
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		m := modules[name]
		pkg := m.Package.Path.String()
		p := byPkg[pkg]
		if p == nil {
			p = &Policy{ID: policyID(pkg), File: name, Builtin: builtin[name]}
			byPkg[pkg] = p
		}
		for _, r := range m.Rules {
			switch r.Head.Ref()[0].String() {
			case "deny":
				p.hasDeny = true
			case "warn":
				p.hasWarn = true
			}
		}
		for _, a := range m.Annotations {
			if a.Scope != "package" && a.Scope != "subpackages" {
				continue
			}
			if err := applyAnnotations(p, a); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}

	var pkgs []string
	for pkg := range byPkg {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		p := byPkg[pkg]
		if !p.hasDeny && !p.hasWarn {
			if !p.Builtin && !isTestPackage(modules, pkg) && pkg != "data.manifesto.lib" {
				e.Warnings = append(e.Warnings, fmt.Sprintf("%s: package %s has no deny or warn rule, so it never reports anything", p.File, strings.TrimPrefix(pkg, "data.")))
			}
			continue
		}
		if p.Severity == "" {
			p.Severity = High
		}

		var q []string
		if p.hasDeny {
			q = append(q, "deny := "+pkg+".deny")
		}
		if p.hasWarn {
			q = append(q, "warn := "+pkg+".warn")
		}
		pq, err := rego.New(
			rego.Compiler(compiler),
			rego.Store(store),
			rego.Query(strings.Join(q, "; ")),
			rego.EnablePrintStatements(true),
			rego.PrintHook(topdown.NewPrintHook(printer)),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("preparing %s: %w", p.ID, err)
		}
		p.query = pq
		e.Policies = append(e.Policies, p)
	}
	return e, nil
}

func policyID(pkg string) string {
	id := strings.TrimPrefix(pkg, "data.")
	return strings.TrimPrefix(id, "manifesto.")
}

func isTestPackage(modules map[string]*ast.Module, pkg string) bool {
	for _, m := range modules {
		if m.Package.Path.String() != pkg {
			continue
		}
		for _, r := range m.Rules {
			if strings.HasPrefix(r.Head.Ref()[0].String(), "test_") {
				return true
			}
		}
	}
	return false
}

func applyAnnotations(p *Policy, a *ast.Annotations) error {
	if a.Title != "" {
		p.Title = a.Title
	}
	if v, ok := a.Custom["severity"]; ok {
		s, _ := v.(string)
		s = strings.ToLower(s)
		if Rank(s) < 0 {
			return fmt.Errorf("custom.severity %v: want high, medium, or low", v)
		}
		p.Severity = s
	}
	if v, ok := a.Custom["kinds"]; ok {
		switch k := v.(type) {
		case string:
			p.Kinds = []string{k}
		case []any:
			for _, item := range k {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("custom.kinds: %v is not a string", item)
				}
				p.Kinds = append(p.Kinds, s)
			}
		default:
			return fmt.Errorf("custom.kinds: want a kind or a list of kinds, got %v", v)
		}
	}
	return nil
}

func formatErrors(errs ast.Errors) string {
	var b strings.Builder
	for _, e := range errs {
		if e.Location != nil {
			fmt.Fprintf(&b, "  %s:%d:%d: %s\n", e.Location.File, e.Location.Row, e.Location.Col, e.Message)
		} else {
			fmt.Fprintf(&b, "  %s\n", e.Message)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p *Policy) Applies(kind string) bool {
	if len(p.Kinds) == 0 {
		return true
	}
	for _, k := range p.Kinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

func (e *Engine) Eval(ctx context.Context, kind string, obj map[string]any) ([]Violation, error) {
	var out []Violation
	for _, p := range e.Policies {
		if !p.Applies(kind) {
			continue
		}
		rs, err := p.query.Eval(ctx, rego.EvalInput(obj))
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.ID, err)
		}
		for _, r := range rs {
			for binding, defaultSev := range map[string]string{"deny": p.Severity, "warn": Low} {
				items, _ := r.Bindings[binding].([]any)
				for _, item := range items {
					v, err := toViolation(p, defaultSev, item)
					if err != nil {
						return nil, err
					}
					out = append(out, v)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Policy.ID != out[j].Policy.ID {
			return out[i].Policy.ID < out[j].Policy.ID
		}
		return out[i].Message < out[j].Message
	})
	return out, nil
}

func toViolation(p *Policy, severity string, item any) (Violation, error) {
	v := Violation{Policy: p, Severity: severity}
	switch t := item.(type) {
	case string:
		v.Message = t
	case map[string]any:
		msg, ok := t["msg"].(string)
		if !ok {
			return v, fmt.Errorf("policy %s: a deny/warn object needs a string \"msg\" field, got %v", p.ID, item)
		}
		v.Message = msg
		v.Path, _ = t["path"].(string)
		if s, ok := t["severity"].(string); ok {
			s = strings.ToLower(s)
			if Rank(s) < 0 {
				return v, fmt.Errorf("policy %s: severity %q: want high, medium, or low", p.ID, s)
			}
			v.Severity = s
		}
	default:
		v.Message = fmt.Sprint(item)
	}
	return v, nil
}
