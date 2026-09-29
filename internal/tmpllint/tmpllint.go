// Package tmpllint checks a chart's raw template source, before rendering,
// for chart-authoring smells a rendered-manifest policy can't see: by the
// time a value is rendered, you can't tell whether it was templated.
//
// Each template is parsed with text/template/parse (the parser Helm itself
// uses), which splits literal text from {{ actions }} and {{/* comments */}}
// exactly. Everything that isn't literal text is masked out, keeping line
// breaks, and the checks then only match values that are literal from start
// to end, with real template line numbers.
package tmpllint

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template/parse"
	"unicode"
)

type Check struct {
	ID       string
	Severity string
	Title    string
	re       *regexp.Regexp
	message  func(value string) string
	exempt   func(value string) bool
}

// mask replaces every byte of template syntax. It can't occur in a chart's
// literal YAML, so a value containing it was (at least partly) templated.
const mask = '\x00'

var Checks = []Check{
	{
		ID: "tmpl.hardcoded_image", Severity: "medium",
		Title: "Images are templated from values, not hardcoded",
		re:    regexp.MustCompile(`^\s*(?:-\s*)?image:\s*["']?([^"'\s\x00]+)["']?\s*$`),
		message: func(v string) string {
			return fmt.Sprintf("image %q is hardcoded: template it from values so users can override registry and tag", v)
		},
	},
	{
		ID: "tmpl.hardcoded_namespace", Severity: "medium",
		Title: "Namespaces come from the release, not a literal",
		re:    regexp.MustCompile(`^\s*namespace:\s*["']?([^"'\s\x00]+)["']?\s*$`),
		message: func(v string) string {
			return fmt.Sprintf("namespace %q is hardcoded: use {{ .Release.Namespace }} so `helm install -n` works", v)
		},
		// Charts that monitor or patch cluster components (CoreDNS metrics,
		// the kube-system kubelet Service) must name these namespaces;
		// kube-prometheus-stack alone has 16 such templates.
		exempt: func(v string) bool { return strings.HasPrefix(v, "kube-") },
	},
}

type Finding struct {
	Policy   string
	Severity string
	Message  string
	File     string
	Line     int
	Ignored  bool
}

// Vendored subcharts under charts/ aren't the author's code, so they aren't
// scanned.
func Chart(chartDir string) ([]Finding, error) {
	root := filepath.Join(chartDir, "templates")
	if _, err := os.Stat(root); err != nil {
		return nil, nil
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var out []Finding
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		fs, err := Source(f, string(src))
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func Source(name, src string) ([]Finding, error) {
	masked, ignores, err := literalOnly(name, src)
	if err != nil {
		// Helm would fail to render this file too; that error is reported
		// by the render step, with better context than we have here.
		return nil, nil
	}
	var out []Finding
	for i, line := range strings.Split(masked, "\n") {
		for _, c := range Checks {
			if m := c.re.FindStringSubmatch(line); m != nil && (c.exempt == nil || !c.exempt(m[1])) {
				out = append(out, Finding{
					Policy: c.ID, Severity: c.Severity, Message: c.message(m[1]), File: name, Line: i + 1,
					Ignored: ignores[i+1][c.ID] || ignores[i+1]["all"],
				})
			}
		}
	}
	return out, nil
}

const ignoreDirective = "manifesto:ignore"

// A `{{/* manifesto:ignore ID[, ID] */}}` comment covers the line it ends on
// and the next one, so it can sit beside a value or above it.
//
// Newlines survive masking so line numbers are unchanged. A comment is
// blanked to spaces instead, so a trailing comment does not hide the literal
// value before it from the checks.
func literalOnly(name, src string) (string, map[int]map[string]bool, error) {
	t := parse.New(name)
	// Helm registers its funcs at render time; here only the tree shape
	// matters, so unknown function names mustn't fail the parse.
	t.Mode = parse.ParseComments | parse.SkipFuncCheck
	trees := map[string]*parse.Tree{}
	if _, err := t.Parse(src, "", "", trees); err != nil {
		return "", nil, err
	}

	m := marker{literal: make([]bool, len(src))}
	for _, tree := range trees {
		m.mark(tree.Root)
	}
	b := []byte(src)
	for i := range b {
		if !m.literal[i] && b[i] != '\n' {
			b[i] = mask
		}
	}

	ignores := map[int]map[string]bool{}
	for _, c := range m.comments {
		pos := int(c.Pos)
		start := strings.LastIndex(src[:pos], "{{")
		n := strings.Index(src[pos:], "}}")
		if start < 0 || n < 0 {
			continue
		}
		end := pos + n + 2
		for i := start; i < end; i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
		text := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(c.Text), "/*"), "*/")
		_, rest, ok := strings.Cut(text, ignoreDirective)
		if !ok {
			continue
		}
		line := 1 + strings.Count(src[:end], "\n")
		for _, id := range strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
			for _, l := range []int{line, line + 1} {
				if ignores[l] == nil {
					ignores[l] = map[string]bool{}
				}
				ignores[l][id] = true
			}
		}
	}
	return string(b), ignores, nil
}

type marker struct {
	literal  []bool
	comments []*parse.CommentNode
}

func (m *marker) mark(n parse.Node) {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			m.mark(c)
		}
	case *parse.TextNode:
		start := int(n.Pos)
		for i := start; i < start+len(n.Text) && i < len(m.literal); i++ {
			m.literal[i] = true
		}
	case *parse.CommentNode:
		m.comments = append(m.comments, n)
	case *parse.IfNode:
		m.mark(n.List)
		m.mark(n.ElseList)
	case *parse.RangeNode:
		m.mark(n.List)
		m.mark(n.ElseList)
	case *parse.WithNode:
		m.mark(n.List)
		m.mark(n.ElseList)
	}
}
