package report

import (
	"io"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/likesavabutworse/manifesto/internal/policy"
)

const infoURI = "https://github.com/likesavabutworse/manifesto"

var sarifLevel = map[string]string{policy.High: "error", policy.Medium: "warning", policy.Low: "note"}

func SARIF(w io.Writer, fs []Finding, version string) error {
	Sort(fs)
	run := sarif.NewRunWithInformationURI("manifesto", infoURI)
	run.Tool.Driver.WithVersion(version)

	seen := map[string]bool{}
	for _, f := range fs {
		if !seen[f.Policy] {
			seen[f.Policy] = true
			rule := run.AddRule(f.Policy).
				WithName(f.Policy).
				WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(sarifLevel[f.Severity]))
			if f.Title != "" {
				rule.WithShortDescription(sarif.NewMultiformatMessageString().WithText(f.Title))
			}
		}

		msg := f.Message
		if f.Resource != "" {
			msg = f.Resource + ": " + msg
		}
		phys := sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.File))
		// SARIF regions are 1-based; with no line, the finding is
		// file-level, which code scanning shows at the top of the file.
		if f.Line > 0 {
			phys.WithRegion(sarif.NewSimpleRegion(f.Line, f.Line))
		}
		loc := sarif.NewLocationWithPhysicalLocation(phys)
		if f.Resource != "" {
			loc.WithLogicalLocations([]*sarif.LogicalLocation{
				sarif.NewLogicalLocation().WithFullyQualifiedName(f.Resource).WithKind("resource"),
			})
		}
		run.AddDistinctArtifact(f.File)
		run.CreateResultForRule(f.Policy).
			WithLevel(sarifLevel[f.Severity]).
			WithMessage(sarif.NewTextMessage(msg)).
			AddLocation(loc)
	}

	log := report.NewV210Report()
	log.AddRun(run)
	return log.PrettyWrite(w)
}
