// Package report renders findings and decides the exit code.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/likesavabutworse/manifesto/internal/policy"
)

type Finding struct {
	Policy   string `json:"policy"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	// Resource is "Kind/name"; empty for template-source findings.
	Resource  string `json:"resource,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type Summary struct {
	Resources int           `json:"resources"`
	Policies  int           `json:"policies"`
	Ignored   int           `json:"ignored"`
	Elapsed   time.Duration `json:"-"`
}

func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line && a.Resource == "" && b.Resource == "" {
			return a.Line < b.Line
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if policy.Rank(a.Severity) != policy.Rank(b.Severity) {
			return policy.Rank(a.Severity) < policy.Rank(b.Severity)
		}
		return a.Policy < b.Policy
	})
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

type painter bool

func (p painter) paint(color, s string) string {
	if !p {
		return s
	}
	return color + s + reset
}

var sevColor = map[string]string{policy.High: red, policy.Medium: yellow, policy.Low: cyan}

func Text(w io.Writer, fs []Finding, s Summary, color bool) {
	p := painter(color)
	Sort(fs)

	idWidth := 0
	for _, f := range fs {
		idWidth = max(idWidth, len(f.Policy))
	}

	var lastFile, lastResource string
	for i, f := range fs {
		if f.File != lastFile {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, p.paint(bold, f.File))
			lastFile, lastResource = f.File, ""
		}
		indent := "  "
		if f.Resource != "" {
			if f.Resource != lastResource {
				label := f.Resource
				if f.Namespace != "" {
					label += p.paint(dim, " -n "+f.Namespace)
				}
				if f.Line > 0 {
					label += p.paint(dim, fmt.Sprintf(" (line %d)", f.Line))
				}
				fmt.Fprintf(w, "  %s\n", label)
				lastResource = f.Resource
			}
			indent = "    "
		}

		sev := fmt.Sprintf("%-6s", f.Severity)
		id := fmt.Sprintf("%-*s", idWidth, f.Policy)
		msg := f.Message
		if f.Resource == "" && f.Line > 0 {
			msg = p.paint(dim, fmt.Sprintf("line %d: ", f.Line)) + msg
		}
		if f.Path != "" {
			msg += p.paint(dim, " ("+f.Path+")")
		}
		fmt.Fprintf(w, "%s%s  %s  %s\n", indent, p.paint(sevColor[f.Severity], sev), p.paint(dim, id), msg)
	}
	if len(fs) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, summaryLine(fs, s, p))
}

func summaryLine(fs []Finding, s Summary, p painter) string {
	counts := map[string]int{}
	affected := map[string]bool{}
	for _, f := range fs {
		counts[f.Severity]++
		if f.Resource != "" {
			affected[f.File+"\x00"+f.Resource] = true
		}
	}
	var tail []string
	tail = append(tail, plural(s.Resources, "resource", "resources"), plural(s.Policies, "policy", "policies"))
	if s.Ignored > 0 {
		tail = append(tail, fmt.Sprintf("%d ignored", s.Ignored))
	}
	tail = append(tail, s.Elapsed.Round(time.Millisecond).String())
	meta := p.paint(dim, strings.Join(tail, " · "))

	if len(fs) == 0 {
		return p.paint(green, "✓ no findings") + "  " + meta
	}
	var parts []string
	for _, sev := range []string{policy.High, policy.Medium, policy.Low} {
		if counts[sev] > 0 {
			parts = append(parts, p.paint(sevColor[sev], fmt.Sprintf("%d %s", counts[sev], sev)))
		}
	}
	return fmt.Sprintf("%s (%s)  %s", p.paint(red, "✗ "+plural(len(fs), "finding", "findings")), strings.Join(parts, ", "), meta)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func JSON(w io.Writer, fs []Finding, s Summary) error {
	Sort(fs)
	if fs == nil {
		fs = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Findings  []Finding `json:"findings"`
		Summary   Summary   `json:"summary"`
		ElapsedMS int64     `json:"elapsed_ms"`
	}{fs, s, s.Elapsed.Milliseconds()})
}

func GitHub(w io.Writer, fs []Finding) {
	Sort(fs)
	level := map[string]string{policy.High: "error", policy.Medium: "warning", policy.Low: "notice"}
	for _, f := range fs {
		props := "file=" + escapeProp(f.File)
		if f.Line > 0 {
			props += fmt.Sprintf(",line=%d", f.Line)
		}
		props += ",title=" + escapeProp("manifesto "+f.Policy)
		msg := f.Message
		if f.Resource != "" {
			msg = f.Resource + ": " + msg
		}
		fmt.Fprintf(w, "::%s %s::%s\n", level[f.Severity], props, escapeData(msg))
	}
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProp(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

func ExitCode(fs []Finding, failOn string) int {
	if failOn == "never" {
		return 0
	}
	threshold := policy.Rank(failOn)
	for _, f := range fs {
		if policy.Rank(f.Severity) <= threshold {
			return 1
		}
	}
	return 0
}
