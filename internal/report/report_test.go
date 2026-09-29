package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

var sample = []Finding{
	{Policy: "k8s.probes", Title: "probes", Severity: "medium", Message: "no probe", File: "chart/templates/d.yaml", Resource: "Deployment/web"},
	{Policy: "tmpl.hardcoded_image", Severity: "medium", Message: "hardcoded", File: "chart/templates/d.yaml", Line: 12},
	{Policy: "pss.privileged", Severity: "high", Message: "privileged", File: "chart/templates/d.yaml", Resource: "Deployment/web"},
}

func TestSARIFIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, append([]Finding(nil), sample...), "test"); err != nil {
		t.Fatal(err)
	}
	log, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Validate(); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
	run := log.Runs[0]
	if len(run.Results) != 3 || len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("got %d results, %d rules", len(run.Results), len(run.Tool.Driver.Rules))
	}
}

func TestExitCode(t *testing.T) {
	for failOn, want := range map[string]int{"high": 1, "medium": 1, "low": 1, "never": 0} {
		if got := ExitCode(sample, failOn); got != want {
			t.Errorf("--fail-on %s: got %d, want %d", failOn, got, want)
		}
	}
	if got := ExitCode(sample[:2], "high"); got != 0 {
		t.Errorf("only medium findings with --fail-on high: got %d", got)
	}
}

func TestTextGroupsByFileThenResource(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, append([]Finding(nil), sample...), Summary{Resources: 1, Policies: 3}, false)
	out := buf.String()
	if strings.Count(out, "chart/templates/d.yaml") != 1 || strings.Count(out, "Deployment/web") != 1 {
		t.Errorf("file and resource should each be printed once:\n%s", out)
	}
	if !strings.Contains(out, "3 findings (1 high, 2 medium)") {
		t.Errorf("bad summary:\n%s", out)
	}
}

func TestGitHubEscaping(t *testing.T) {
	var buf bytes.Buffer
	GitHub(&buf, []Finding{{Policy: "p", Severity: "high", Message: "100% bad\nnext", File: "a,b.yaml"}})
	if got := buf.String(); got != "::error file=a%2Cb.yaml,title=manifesto p::100%25 bad%0Anext\n" {
		t.Errorf("got %q", got)
	}
}
