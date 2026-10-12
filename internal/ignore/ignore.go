// Package ignore reads the ignore file: exceptions kept in the repository,
// for findings in a chart the person scanning it does not own, so cannot
// annotate.
package ignore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultPath = ".manifesto/ignore.yaml"

// Entry ignores the findings that match all of its set fields. Every field
// is a glob where * matches any run of characters, including "/".
type Entry struct {
	Policy    string `yaml:"policy"`
	Resource  string `yaml:"resource"`  // "Kind/name"
	File      string `yaml:"file"`      // matches the whole path or any tail of it
	Namespace string `yaml:"namespace"` // as written in the manifest
	Reason    string `yaml:"reason"`

	hits int

	// Globs are compiled once at Load, not per Match call: a scan can run
	// Match once per finding, and these patterns never change in between.
	// A nil field (an unset glob) always matches.
	policyRe, resourceRe, namespaceRe, fileRe *regexp.Regexp
}

type List struct {
	Path    string
	Entries []*Entry
}

// Load reads path. A missing DefaultPath is not an error; a missing file the
// user named is.
func Load(path string) (*List, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultPath
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return &List{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ignore file: %w", pathError(err))
	}

	var doc struct {
		Ignore []*Entry `yaml:"ignore"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, e := range doc.Ignore {
		switch {
		case e == nil, e.Policy == "":
			return nil, fmt.Errorf("%s: ignore[%d]: policy is required (a policy ID, or a glob such as pss.*)", path, i)
		case strings.TrimSpace(e.Reason) == "":
			return nil, fmt.Errorf("%s: ignore[%d] (%s): reason is required, so the next reader knows why", path, i, e.Policy)
		}
		for _, f := range []struct {
			pattern string
			re      **regexp.Regexp
		}{
			{e.Policy, &e.policyRe}, {e.Resource, &e.resourceRe},
			{e.Namespace, &e.namespaceRe}, {e.File, &e.fileRe},
		} {
			if f.pattern == "" {
				continue
			}
			re, err := compileGlob(f.pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: ignore[%d]: %q: %w", path, i, f.pattern, err)
			}
			*f.re = re
		}
	}
	return &List{Path: path, Entries: doc.Ignore}, nil
}

func (l *List) Match(policy, file, resource, namespace string) bool {
	matched := false
	for _, e := range l.Entries {
		if e.policyRe.MatchString(policy) &&
			(e.resourceRe == nil || e.resourceRe.MatchString(resource)) &&
			(e.namespaceRe == nil || e.namespaceRe.MatchString(namespace)) &&
			(e.fileRe == nil || fileMatches(e.fileRe, file)) {
			e.hits++
			matched = true
		}
	}
	return matched
}

// Entries that match nothing are usually left behind after the chart or the
// policy changed.
func (l *List) Unused() []string {
	var out []string
	for i, e := range l.Entries {
		if e.hits == 0 {
			out = append(out, fmt.Sprintf("%s: ignore[%d] (%s) matched no finding", l.Path, i, e.Policy))
		}
	}
	return out
}

// fileMatches lets "templates/x.yaml" match however the chart was named on
// the command line ("./chart/templates/x.yaml").
func fileMatches(re *regexp.Regexp, file string) bool {
	if re.MatchString(file) {
		return true
	}
	for i, c := range file {
		if c == '/' && re.MatchString(file[i+1:]) {
			return true
		}
	}
	return false
}

// compileGlob turns a glob (* matches any run of characters, including "/")
// into a compiled regexp, once, at Load time.
func compileGlob(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$")
}

func pathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}
