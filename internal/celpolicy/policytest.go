package celpolicy

import (
	"context"
	"fmt"
	"strings"
)

const (
	testAPIVersion = "manifesto.io/v1"
	testKind       = "PolicyTest"
)

// A ValidatingAdmissionPolicy has no unit-test format of its own, so a
// PolicyTest fills the gap that Rego's test_ rules fill.
type Suite struct {
	Name   string
	Policy string
	File   string
	Cases  []Case
}

type Case struct {
	Name    string         `json:"name"`
	Object  map[string]any `json:"object"`
	Expect  string         `json:"expect"`
	Message string         `json:"message"`
}

type TestResult struct {
	Policy, Case string
	Err          error // nil when the case passed
}

// Objects go through the same JSON round trip as a rendered chart (convert),
// so numbers have the types a policy sees in a real scan.
func LoadTests(dirs []string) ([]Suite, error) {
	var suites []Suite
	for _, dir := range dirs {
		err := walkDocs(dir, func(p string, doc map[string]any) error {
			if doc["apiVersion"] != testAPIVersion || doc["kind"] != testKind {
				return nil
			}
			var raw struct {
				Metadata struct{ Name string } `json:"metadata"`
				Policy   string                `json:"policy"`
				Cases    []Case                `json:"cases"`
			}
			if err := convert(doc, &raw); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if raw.Policy == "" {
				return fmt.Errorf("%s: PolicyTest needs a policy: the name of the ValidatingAdmissionPolicy it tests", p)
			}
			for i, c := range raw.Cases {
				if c.Expect != "pass" && c.Expect != "fail" {
					return fmt.Errorf("%s: cases[%d] %q: expect is %q, want pass or fail", p, i, c.Name, c.Expect)
				}
				if c.Object == nil {
					return fmt.Errorf("%s: cases[%d] %q: object is required", p, i, c.Name)
				}
			}
			suites = append(suites, Suite{Name: raw.Metadata.Name, Policy: raw.Policy, File: p, Cases: raw.Cases})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("loading CEL policy tests from %s: %w", dir, err)
		}
	}
	return suites, nil
}

func (e *Engine) RunTests(ctx context.Context, suites []Suite) []TestResult {
	var out []TestResult
	for _, s := range suites {
		var pol *Policy
		for _, p := range e.Policies {
			if p.ID == s.Policy {
				pol = p
			}
		}
		for _, c := range s.Cases {
			r := TestResult{Policy: s.Policy, Case: c.Name}
			if pol == nil {
				r.Err = fmt.Errorf("%s: no policy named %q in the policy directories", s.File, s.Policy)
			} else {
				r.Err = runCase(ctx, pol, c)
			}
			out = append(out, r)
		}
	}
	return out
}

func runCase(ctx context.Context, p *Policy, c Case) error {
	vs, err := p.eval(ctx, toUnstructured(c.Object).(map[string]any))
	if err != nil {
		return err
	}
	switch {
	case c.Expect == "pass" && len(vs) > 0:
		return fmt.Errorf("expected no findings, got: %s", vs[0].Message)
	case c.Expect == "fail" && len(vs) == 0:
		return fmt.Errorf("expected a finding, got none (does the object match the policy's matchConstraints?)")
	case c.Expect == "fail" && c.Message != "":
		for _, v := range vs {
			if strings.Contains(v.Message, c.Message) {
				return nil
			}
		}
		return fmt.Errorf("no finding contains %q; got: %s", c.Message, vs[0].Message)
	}
	return nil
}
