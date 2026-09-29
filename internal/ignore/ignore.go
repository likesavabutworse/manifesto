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
	}
	return &List{Path: path, Entries: doc.Ignore}, nil
}

func (l *List) Match(policy, file, resource, namespace string) bool {
	matched := false
	for _, e := range l.Entries {
		if glob(e.Policy, policy) &&
			(e.Resource == "" || glob(e.Resource, resource)) &&
			(e.Namespace == "" || glob(e.Namespace, namespace)) &&
			(e.File == "" || fileMatches(e.File, file)) {
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
func fileMatches(pattern, file string) bool {
	if glob(pattern, file) {
		return true
	}
	for i, c := range file {
		if c == '/' && glob(pattern, file[i+1:]) {
			return true
		}
	}
	return false
}

func glob(pattern, s string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

func pathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}
