// Package manifest turns a Helm chart (rendered in-process with the Helm
// SDK) or a set of already-rendered YAML files into a flat list of
// Resources, each carrying enough location context to point a finding back
// at its source.
package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/loader"
	chartv2 "helm.sh/helm/v4/pkg/chart/v2"
	chartloader "helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/engine"
	release "helm.sh/helm/v4/pkg/release/v1"
	releaseutil "helm.sh/helm/v4/pkg/release/v1/util"
	"helm.sh/helm/v4/pkg/strvals"
)

type Resource struct {
	Kind      string
	Name      string
	Namespace string

	File string
	// Line is the object's first line in File. Always 0 in chart mode:
	// rendered line numbers don't correspond to template line numbers, and
	// printing them against the template path (as some scanners do) points
	// at the wrong code.
	Line int

	// Object is the resource normalized through a JSON round-trip, so every
	// value is a JSON type (map[string]any, []any, float64, string, bool).
	Object map[string]any
}

func (r Resource) ID() string {
	if r.Name == "" {
		return r.Kind
	}
	return r.Kind + "/" + r.Name
}

type RenderOptions struct {
	Release      string
	Namespace    string
	ValuesFiles  []string
	Set          []string
	SetString    []string
	KubeVersion  string
	APIVersions  []string
	IncludeTests bool
}

func IsChart(path string) bool {
	_, err := os.Stat(filepath.Join(path, "Chart.yaml"))
	return err == nil
}

// It does not use pkg/action, which drags in the cluster client, storage
// drivers and provenance code.
func RenderChart(ctx context.Context, chartPath string, opts RenderOptions) ([]Resource, error) {
	loaded, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("loading chart: %w", err)
	}
	ch, ok := loaded.(*chartv2.Chart)
	if !ok {
		return nil, fmt.Errorf("unsupported chart type %T", loaded)
	}
	if t := ch.Metadata.Type; t != "" && t != "application" {
		return nil, fmt.Errorf("%s is a %v chart, which renders nothing on its own; scan a chart that uses it", chartPath, t)
	}
	if err := checkDependencies(ch); err != nil {
		return nil, fmt.Errorf("%w; run `helm dependency build %s` first", err, chartPath)
	}

	vals, err := mergeValues(opts)
	if err != nil {
		return nil, err
	}
	if err := chartutil.ProcessDependencies(ch, vals); err != nil {
		return nil, fmt.Errorf("chart dependencies processing failed: %w", err)
	}

	caps := common.DefaultCapabilities.Copy()
	if opts.KubeVersion != "" {
		kv, err := common.ParseKubeVersion(opts.KubeVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid kube version %q: %w", opts.KubeVersion, err)
		}
		caps.KubeVersion = *kv
	}
	caps.APIVersions = append(caps.APIVersions, opts.APIVersions...)
	if c := ch.Metadata.KubeVersion; c != "" && !chartutil.IsCompatibleRange(c, caps.KubeVersion.String()) {
		return nil, fmt.Errorf("chart requires kubeVersion: %s which is incompatible with Kubernetes %s (change the assumed version with --kube-version)", c, caps.KubeVersion.Version)
	}

	relName := opts.Release
	if relName == "" {
		relName = "release-name"
	}
	ns := opts.Namespace
	if ns == "" {
		ns = "default"
	}
	renderVals, err := util.ToRenderValuesWithSchemaValidation(ch, vals, common.ReleaseOptions{
		Name: relName, Namespace: ns, Revision: 1, IsInstall: true,
	}, caps, false)
	if err != nil {
		// Helm's schema error ends in blank lines.
		return nil, errors.New(strings.TrimSpace(err.Error()))
	}

	var eng engine.Engine
	files, err := eng.RenderWithContext(ctx, ch, renderVals)
	if err != nil {
		return nil, fmt.Errorf("rendering chart: %w", err)
	}
	// NOTES.txt is text, not a manifest.
	maps.DeleteFunc(files, func(name, _ string) bool { return strings.HasSuffix(name, "NOTES.txt") })

	hooks, manifests, err := releaseutil.SortManifests(files, nil, releaseutil.InstallOrder)
	if err != nil {
		return nil, fmt.Errorf("rendering chart: %w", err)
	}

	var doc strings.Builder
	for _, m := range manifests {
		fmt.Fprintf(&doc, "---\n# Source: %s\n%s\n", m.Name, m.Content)
	}
	out, err := Parse([]byte(doc.String()), "", chartPath)
	if err != nil {
		return nil, err
	}
	for _, h := range hooks {
		// Test hook pods are throwaway busybox containers; scanning them
		// buries real findings under missing-probe/limit noise.
		if !opts.IncludeTests && slices.Contains(h.Events, release.HookTest) {
			continue
		}
		rs, err := Parse([]byte(h.Manifest), chartRelative(chartPath, h.Path), "")
		if err != nil {
			return nil, err
		}
		for i := range rs {
			rs[i].Line = 0
		}
		out = append(out, rs...)
	}
	return out, nil
}

func checkDependencies(ch *chartv2.Chart) error {
	have := map[string]bool{}
	for _, d := range ch.Dependencies() {
		have[d.Name()] = true
	}
	var missing []string
	for _, r := range ch.Metadata.Dependencies {
		if !have[r.Name] {
			missing = append(missing, r.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("dependencies listed in Chart.yaml are missing from charts/: %s", strings.Join(missing, ", "))
	}
	return nil
}

// URLs are not accepted as values files: that would need Helm's getter
// providers, and the plugin runtime they pull into the binary.
func mergeValues(opts RenderOptions) (map[string]any, error) {
	base := map[string]any{}
	for _, f := range opts.ValuesFiles {
		var raw []byte
		var err error
		if strings.TrimSpace(f) == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(f)
		}
		if err != nil {
			return nil, fmt.Errorf("values file %w", pathError(err))
		}
		cur, err := chartloader.LoadValues(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", f, err)
		}
		base = chartloader.MergeMaps(base, cur)
	}
	for _, v := range opts.Set {
		if err := strvals.ParseInto(v, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set data: %w", err)
		}
	}
	for _, v := range opts.SetString {
		if err := strvals.ParseIntoString(v, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-string data: %w", err)
		}
	}
	return base, nil
}

// pathError words an os error as "<path>: <reason>", without the "open" or
// "stat" verb that means nothing to someone who typed a command line.
func pathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}

// Helm names templates "<chart-name>/templates/x.yaml"; that prefix is not a
// directory on disk.
func chartRelative(chartRoot, source string) string {
	if _, rest, ok := strings.Cut(source, "/"); ok {
		return filepath.Join(chartRoot, rest)
	}
	return source
}

// Input piped from `helm template` keeps its "# Source:" template attribution.
func LoadPath(path string) ([]Resource, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return Parse(b, "<stdin>", "")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, pathError(err)
	}
	var files []string
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			ext := strings.ToLower(filepath.Ext(p))
			if !d.IsDir() && (ext == ".yaml" || ext == ".yml") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var out []Resource
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rs, err := Parse(b, f, "")
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

// Parse decodes a multi-document YAML stream into Resources. file names the
// stream for location reporting. For a stream with no file of its own (a
// chart render, or stdin), a "# Source:" comment emitted by Helm names the
// template instead; a real file keeps its own path and line numbers, since
// those are what an editor can open. chartRoot, when set, maps Source paths
// under the chart directory.
func Parse(data []byte, file, chartRoot string) ([]Resource, error) {
	useSource := file == "" || file == "<stdin>"
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []Resource
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			name := file
			if name == "" {
				name = "rendered chart"
			}
			return nil, fmt.Errorf("%s: invalid YAML: %w", name, err)
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]

		src := file
		if useSource {
			if s := sourceComment(&doc); s != "" {
				src = s
				if chartRoot != "" {
					src = chartRelative(chartRoot, s)
				}
			}
		}

		var raw any
		if err := root.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", src, root.Line, err)
		}
		obj, err := normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", src, root.Line, err)
		}
		if obj == nil {
			continue
		}

		r := Resource{File: src, Object: obj}
		if src == file && file != "" {
			r.Line = root.Line
		}
		r.Kind, _ = obj["kind"].(string)
		if md, ok := obj["metadata"].(map[string]any); ok {
			r.Name, _ = md["name"].(string)
			r.Namespace, _ = md["namespace"].(string)
		}
		if r.Kind == "" {
			// Not a Kubernetes object (e.g. a values file in a manifests
			// dir); nothing a policy could meaningfully target.
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// yaml.v3 attaches a comment above a document's first key to that key, not
// the document.
func sourceComment(doc *yaml.Node) string {
	comments := []string{doc.HeadComment}
	if root := doc.Content[0]; root != nil {
		comments = append(comments, root.HeadComment)
		if len(root.Content) > 0 {
			comments = append(comments, root.Content[0].HeadComment)
		}
	}
	for _, c := range comments {
		for _, line := range strings.Split(c, "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "# Source:"); ok {
				return strings.TrimSpace(rest)
			}
		}
	}
	return ""
}

func normalize(raw any) (map[string]any, error) {
	if _, ok := raw.(map[string]any); !ok {
		// A top-level scalar, list, or empty document: not an object.
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("document is not JSON-representable (non-string map keys?): %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}
