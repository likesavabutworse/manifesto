// Package pss evaluates pod-bearing resources against the Kubernetes Pod
// Security Standards, using the same check implementations the API
// server's PodSecurity admission plugin runs (k8s.io/pod-security-admission).
// A chart that passes here passes a namespace labeled with the same
// pod-security.kubernetes.io/enforce level.
package pss

import (
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/pod-security-admission/api"
	psapolicy "k8s.io/pod-security-admission/policy"
)

type Level string

const (
	Off        Level = "off"
	Baseline   Level = "baseline"
	Restricted Level = "restricted"
)

func ParseLevel(s string) (Level, error) {
	switch l := Level(strings.ToLower(s)); l {
	case Off, Baseline, Restricted:
		return l, nil
	}
	return "", fmt.Errorf("--pss %q: want restricted, baseline, or off", s)
}

// IDPrefix namespaces check IDs so they can be ignored like any policy.
const IDPrefix = "pss."

// Baseline checks block known privilege escalations; restricted checks are
// hardening on top. The severities reflect that gap.
const (
	baselineSeverity   = "high"
	restrictedSeverity = "medium"
)

type Check struct {
	ID       string
	Level    Level
	Severity string
	fn       psapolicy.CheckPodFn
}

type Violation struct {
	Check    Check
	Severity string
	Message  string
}

type Evaluator struct {
	Checks []Check
}

// Restricted checks that tighten a baseline check (e.g.
// capabilities_restricted over capabilities_baseline) replace it, as the
// admission plugin does, so one problem yields one finding.
func New(level Level) *Evaluator {
	if level == Off {
		return &Evaluator{}
	}
	var all []Check
	overridden := map[string]bool{}
	for _, c := range psapolicy.DefaultChecks() {
		if c.Level == api.LevelRestricted && level != Restricted {
			continue
		}
		latest := c.Versions[len(c.Versions)-1]
		ch := Check{ID: IDPrefix + string(c.ID), Level: Baseline, Severity: baselineSeverity, fn: latest.CheckPod}
		if c.Level == api.LevelRestricted {
			ch.Level, ch.Severity = Restricted, restrictedSeverity
		}
		for _, o := range latest.OverrideCheckIDs {
			overridden[IDPrefix+string(o)] = true
		}
		all = append(all, ch)
	}
	e := &Evaluator{}
	for _, c := range all {
		if !overridden[c.ID] {
			e.Checks = append(e.Checks, c)
		}
	}
	return e
}

var podTemplateKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"ReplicaSet": true, "ReplicationController": true, "Job": true,
}

func podTemplate(kind string, obj map[string]any) (meta, spec any, ok bool) {
	switch {
	case kind == "Pod":
		return obj["metadata"], obj["spec"], true
	case podTemplateKinds[kind]:
		t := dig(obj, "spec", "template")
		return dig(t, "metadata"), dig(t, "spec"), t != nil
	case kind == "CronJob":
		t := dig(obj, "spec", "jobTemplate", "spec", "template")
		return dig(t, "metadata"), dig(t, "spec"), t != nil
	}
	return nil, nil, false
}

func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// A pod template that doesn't match the Kubernetes schema (say, a quoted
// runAsUser) yields one finding: the API server would reject it too.
func (e *Evaluator) Evaluate(kind string, obj map[string]any) []Violation {
	if len(e.Checks) == 0 {
		return nil
	}
	rawMeta, rawSpec, ok := podTemplate(kind, obj)
	if !ok || rawSpec == nil {
		return nil
	}
	var meta metav1.ObjectMeta
	var spec corev1.PodSpec
	err := convert(rawMeta, &meta)
	if err == nil {
		err = convert(rawSpec, &spec)
	}
	if err != nil {
		return []Violation{{
			Check:    Check{ID: IDPrefix + "invalid_pod_spec", Level: Baseline, Severity: baselineSeverity},
			Severity: baselineSeverity,
			Message:  "pod template doesn't match the Kubernetes schema: " + err.Error(),
		}}
	}

	var out []Violation
	for _, c := range e.Checks {
		r := c.fn(&meta, &spec)
		if r.Allowed {
			continue
		}
		msg := r.ForbiddenReason
		if r.ForbiddenDetail != "" {
			msg += ": " + r.ForbiddenDetail
		}
		out = append(out, Violation{Check: c, Severity: c.Severity, Message: msg})
	}
	return out
}

func convert(in, out any) error {
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
