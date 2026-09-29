package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/tester"
	"github.com/spf13/cobra"

	"github.com/likesavabutworse/manifesto/internal/celpolicy"
	"github.com/likesavabutworse/manifesto/internal/ignore"
	"github.com/likesavabutworse/manifesto/internal/manifest"
	"github.com/likesavabutworse/manifesto/internal/policy"
	"github.com/likesavabutworse/manifesto/internal/pss"
	"github.com/likesavabutworse/manifesto/internal/report"
	"github.com/likesavabutworse/manifesto/internal/scaffold"
	"github.com/likesavabutworse/manifesto/internal/tmpllint"
)

const ignoreAnnotation = "manifesto.io/ignore"

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// A nil err means the command already reported what it needed to.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(stderr, "error: %v\n", ee.err)
		}
		return ee.code
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 2
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "manifesto",
		Short:         "Policy checks for Helm charts",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SetOut(stderr)
			_ = cmd.Help()
			return &exitError{code: 2}
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(
		newScanCmd(stdout, stderr),
		newNewCmd(stdout),
		newTestCmd(stdout, stderr),
		newPoliciesCmd(stdout),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			Run:   func(*cobra.Command, []string) { fmt.Fprintln(stdout, version) },
		},
	)
	return root
}

func policyDirs(given []string) []string {
	if len(given) > 0 {
		return given
	}
	if info, err := os.Stat(scaffold.DefaultDir); err == nil && info.IsDir() {
		return []string{scaffold.DefaultDir}
	}
	return nil
}

func addPolicyFlag(cmd *cobra.Command, dirs *[]string) {
	cmd.Flags().StringSliceVarP(dirs, "policy", "p", nil, "directory of .rego and ValidatingAdmissionPolicy .yaml policies (repeatable; default "+scaffold.DefaultDir+" if present)")
}

type scanOptions struct {
	render                     manifest.RenderOptions
	policies, ignore           []string
	ignoreFile                 string
	noBuiltins, noTemplateLint bool
	pssLevel, failOn           string
	outputs                    []string
	noColor                    bool
}

func newScanCmd(stdout, stderr io.Writer) *cobra.Command {
	o := &scanOptions{}
	cmd := &cobra.Command{
		Use:   "scan [chart-dir | manifest-file | manifest-dir | -]",
		Short: "Scan a chart (default \".\") or rendered manifests",
		Long: `Scan a Helm chart, rendered in-process exactly as "helm template" would, or
already-rendered manifests (a file, a directory, or "-" for stdin).

Exit status: 0 no findings at or above --fail-on, 1 findings, 2 error.`,
		Example: `  manifesto scan ./chart -f values/prod.yaml
  manifesto scan ./chart --set image.tag=1.2.3 --pss baseline
  helm template ./chart | manifesto scan -
  manifesto scan ./chart -o text -o sarif=manifesto.sarif`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runScan(cmd.Context(), target, o, stdout, stderr)
		},
	}
	f := cmd.Flags()
	f.StringArrayVarP(&o.render.ValuesFiles, "values", "f", nil, "values file for rendering (repeatable)")
	f.StringArrayVar(&o.render.Set, "set", nil, "set values on the command line, as helm --set (repeatable)")
	f.StringArrayVar(&o.render.SetString, "set-string", nil, "set STRING values, as helm --set-string (repeatable)")
	f.StringVar(&o.render.Release, "release", "", "release name (default \"release-name\")")
	f.StringVarP(&o.render.Namespace, "namespace", "n", "", "release namespace (default \"default\")")
	f.StringVar(&o.render.KubeVersion, "kube-version", "", "Kubernetes version for .Capabilities.KubeVersion")
	f.StringSliceVarP(&o.render.APIVersions, "api-versions", "a", nil, "extra API versions for .Capabilities.APIVersions")
	f.BoolVar(&o.render.IncludeTests, "include-tests", false, "also scan helm test hook pods")
	addPolicyFlag(cmd, &o.policies)
	f.StringSliceVar(&o.ignore, "ignore", nil, "policy ID to skip everywhere (repeatable or comma-separated)")
	f.StringVar(&o.ignoreFile, "ignore-file", "", "file of ignore rules (default "+ignore.DefaultPath+" if present)")
	f.BoolVar(&o.noBuiltins, "no-builtins", false, "only run your own policies (disables built-ins, PSS, and template lint)")
	f.BoolVar(&o.noTemplateLint, "no-template-lint", false, "skip checks on the raw template source")
	f.StringVar(&o.pssLevel, "pss", string(pss.Restricted), "Pod Security Standards level: restricted, baseline, or off")
	f.StringVar(&o.failOn, "fail-on", policy.Low, "exit 1 on findings at or above: high, medium, low, never")
	f.StringArrayVarP(&o.outputs, "output", "o", []string{"text"}, "output format[=file]: text, json, github, sarif (repeatable; at most one without a file, which goes to stdout)")
	f.BoolVar(&o.noColor, "no-color", false, "disable color (also honors NO_COLOR)")
	return cmd
}

func runScan(ctx context.Context, target string, o *scanOptions, stdout, stderr io.Writer) error {
	usage := func(format string, a ...any) error {
		return &exitError{code: 2, err: fmt.Errorf(format, a...)}
	}
	if o.failOn != "never" && policy.Rank(o.failOn) < 0 {
		return usage("--fail-on %q: want high, medium, low, or never", o.failOn)
	}
	outputs, err := parseOutputs(o.outputs)
	if err != nil {
		return usage("%v", err)
	}
	level, err := pss.ParseLevel(o.pssLevel)
	if err != nil {
		return usage("%v", err)
	}
	if o.noBuiltins {
		level = pss.Off
	}

	start := time.Now()
	isChart := target != "-" && manifest.IsChart(target)
	var resources []manifest.Resource
	if isChart {
		resources, err = manifest.RenderChart(ctx, target, o.render)
	} else {
		if len(o.render.ValuesFiles) > 0 || len(o.render.Set) > 0 || len(o.render.SetString) > 0 {
			return usage("-f/--set need a chart directory, and %s has no Chart.yaml", target)
		}
		resources, err = manifest.LoadPath(target)
	}
	if err != nil {
		return &exitError{code: 2, err: err}
	}

	if len(resources) == 0 {
		if !isChart {
			where := target
			if target == "-" {
				where = "stdin"
			}
			return usage("no Kubernetes resources found in %s (expected a chart with Chart.yaml, or YAML with apiVersion and kind)", where)
		}
		fmt.Fprintln(stderr, "warning: chart renders no resources; check its values and conditionals")
	}

	objects := make([]map[string]any, len(resources))
	for i, r := range resources {
		objects[i] = r.Object
	}
	engine, err := policy.Load(ctx, policy.Options{
		Dirs: policyDirs(o.policies), NoBuiltins: o.noBuiltins, Resources: objects, Print: stderr,
	})
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	for _, w := range engine.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	celEngine, err := celpolicy.Load(policyDirs(o.policies))
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	evaluator := pss.New(level)

	ignoreList, err := ignore.Load(o.ignoreFile)
	if err != nil {
		return usage("%v", err)
	}
	globalIgnore := map[string]bool{}
	for _, id := range o.ignore {
		globalIgnore[strings.TrimSpace(id)] = true
	}

	var findings []report.Finding
	ignored := 0
	for _, r := range resources {
		local := resourceIgnores(r)
		add := func(f report.Finding) {
			f.File, f.Line, f.Resource, f.Namespace = r.File, r.Line, r.ID(), r.Namespace
			if globalIgnore[f.Policy] || local[f.Policy] || local["all"] ||
				ignoreList.Match(f.Policy, f.File, f.Resource, f.Namespace) {
				ignored++
				return
			}
			findings = append(findings, f)
		}

		violations, err := engine.Eval(ctx, r.Kind, r.Object)
		if err != nil {
			return &exitError{code: 2, err: fmt.Errorf("%s (%s): %w", r.File, r.ID(), err)}
		}
		for _, v := range violations {
			add(report.Finding{Policy: v.Policy.ID, Title: v.Policy.Title, Severity: v.Severity, Message: v.Message, Path: v.Path})
		}
		celViolations, err := celEngine.Eval(ctx, r.Object)
		if err != nil {
			return &exitError{code: 2, err: fmt.Errorf("%s (%s): %w", r.File, r.ID(), err)}
		}
		for _, v := range celViolations {
			add(report.Finding{Policy: v.Policy.ID, Title: v.Policy.Title, Severity: v.Severity, Message: v.Message})
		}
		for _, v := range evaluator.Evaluate(r.Kind, r.Object) {
			add(report.Finding{Policy: v.Check.ID, Title: pssTitle(v.Check), Severity: v.Severity, Message: v.Message})
		}
	}

	if isChart && !o.noTemplateLint && !o.noBuiltins {
		lint, err := tmpllint.Chart(target)
		if err != nil {
			return &exitError{code: 2, err: err}
		}
		for _, f := range lint {
			if f.Ignored || globalIgnore[f.Policy] || ignoreList.Match(f.Policy, f.File, "", "") {
				ignored++
				continue
			}
			findings = append(findings, report.Finding{
				Policy: f.Policy, Severity: f.Severity, Message: f.Message, File: f.File, Line: f.Line,
			})
		}
	}

	for _, w := range ignoreList.Unused() {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	summary := report.Summary{
		Resources: len(resources), Policies: len(engine.Policies) + len(celEngine.Policies) + len(evaluator.Checks),
		Ignored: ignored, Elapsed: time.Since(start),
	}
	for _, out := range outputs {
		if err := out.write(stdout, findings, summary, o.noColor); err != nil {
			return &exitError{code: 2, err: err}
		}
	}
	if code := report.ExitCode(findings, o.failOn); code != 0 {
		return &exitError{code: code}
	}
	return nil
}

type output struct{ format, path string }

// parseOutputs is strict up front so a typo fails before the render, not
// after it. Two outputs on stdout would interleave, so only one is allowed.
func parseOutputs(specs []string) ([]output, error) {
	var outs []output
	toStdout := 0
	for _, s := range specs {
		format, path, _ := strings.Cut(s, "=")
		switch format {
		case "text", "json", "github", "sarif":
		default:
			return nil, fmt.Errorf("--output %q: want text, json, github, or sarif, optionally as format=file", s)
		}
		if path == "" {
			toStdout++
		}
		outs = append(outs, output{format, path})
	}
	if toStdout > 1 {
		return nil, errors.New("--output: only one format can go to stdout; give the others a file, e.g. -o sarif=manifesto.sarif")
	}
	return outs, nil
}

func (o output) write(stdout io.Writer, findings []report.Finding, summary report.Summary, noColor bool) (err error) {
	w := stdout
	if o.path != "" {
		f, err := os.Create(o.path)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, f.Close()) }()
		w = f
	}
	switch o.format {
	case "json":
		return report.JSON(w, findings, summary)
	case "sarif":
		return report.SARIF(w, findings, version)
	case "github":
		report.GitHub(w, findings)
	default:
		report.Text(w, findings, summary, useColor(w, noColor))
	}
	return nil
}

func pssTitle(c pss.Check) string {
	return fmt.Sprintf("Pod Security Standards (%s): %s", c.Level, strings.TrimPrefix(c.ID, pss.IDPrefix))
}

func resourceIgnores(r manifest.Resource) map[string]bool {
	out := map[string]bool{}
	md, _ := r.Object["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	if v, ok := ann[ignoreAnnotation].(string); ok {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				out[id] = true
			}
		}
	}
	return out
}

func useColor(w io.Writer, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func newNewCmd(stdout io.Writer) *cobra.Command {
	var kinds []string
	var dir string
	cmd := &cobra.Command{
		Use:     "new <name>",
		Short:   "Scaffold a custom policy and its test",
		Example: `  manifesto new require-team-label --kind Deployment,StatefulSet`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			policyPath, testPath, err := scaffold.Write(dir, args[0], kinds)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			pkg := scaffold.PackageName(args[0])
			fmt.Fprintf(stdout, "created %s\ncreated %s\n\n", policyPath, testPath)
			fmt.Fprintf(stdout, "Next:\n  1. edit the deny rule in %s\n  2. manifesto test                # run its unit tests\n  3. manifesto scan ./your-chart   # findings show up as %q\n", policyPath, pkg)
			if dir != scaffold.DefaultDir {
				fmt.Fprintf(stdout, "\n%s is not the default policy dir; pass --policy %s to test and scan.\n", dir, dir)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&kinds, "kind", nil, "resource kind(s) the policy targets (default Deployment,StatefulSet,DaemonSet)")
	cmd.Flags().StringVar(&dir, "dir", scaffold.DefaultDir, "where to write the policy")
	return cmd
}

func newTestCmd(stdout, stderr io.Writer) *cobra.Command {
	var policies []string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "test [policy-dir]...",
		Short: "Run policy unit tests (Rego test_* rules and CEL PolicyTest files)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs := policyDirs(append(policies, args...))
			if len(dirs) == 0 {
				return &exitError{code: 2, err: fmt.Errorf("no policies: %s does not exist; create one with `manifesto new <name>` or pass --policy", scaffold.DefaultDir)}
			}
			modules, _, err := policy.LoadModules(dirs, false)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			ch, err := tester.NewRunner().
				SetCompiler(ast.NewCompiler().WithEnablePrintStatements(true)).
				Run(cmd.Context(), modules)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			celEngine, err := celpolicy.Load(dirs)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			suites, err := celpolicy.LoadTests(dirs)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			pass, fail := 0, 0
			for _, r := range celEngine.RunTests(cmd.Context(), suites) {
				name := r.Policy + ": " + r.Case
				if r.Err != nil {
					fail++
					fmt.Fprintf(stdout, "FAIL  %s\n      %v\n", name, r.Err)
					continue
				}
				pass++
				if verbose {
					fmt.Fprintf(stdout, "PASS  %s\n", name)
				}
			}
			for r := range ch {
				name := strings.TrimPrefix(r.Package, "data.") + "." + r.Name
				switch {
				case r.Error != nil:
					fail++
					fmt.Fprintf(stdout, "ERROR %s: %v\n", name, r.Error)
				case r.Fail:
					fail++
					fmt.Fprintf(stdout, "FAIL  %s (%s:%d)\n", name, r.Location.File, r.Location.Row)
				case r.Skip:
					fmt.Fprintf(stdout, "SKIP  %s\n", name)
				default:
					pass++
					if verbose {
						fmt.Fprintf(stdout, "PASS  %s\n", name)
					}
				}
				if len(r.Output) > 0 {
					fmt.Fprintf(stdout, "      %s\n", strings.ReplaceAll(strings.TrimRight(string(r.Output), "\n"), "\n", "\n      "))
				}
			}
			fmt.Fprintf(stdout, "%d passed, %d failed\n", pass, fail)
			if fail > 0 {
				return &exitError{code: 1}
			}
			if pass == 0 {
				fmt.Fprintln(stderr, "no tests found (test rules are named test_*)")
			}
			return nil
		},
	}
	addPolicyFlag(cmd, &policies)
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "list passing tests too")
	return cmd
}

func newPoliciesCmd(stdout io.Writer) *cobra.Command {
	var policies []string
	var pssLevel string
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "List every check a scan runs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			level, err := pss.ParseLevel(pssLevel)
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			engine, err := policy.Load(cmd.Context(), policy.Options{Dirs: policyDirs(policies)})
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tAPPLIES TO\tTITLE")
			for _, p := range engine.Policies {
				kinds := "*"
				if len(p.Kinds) > 0 {
					kinds = strings.Join(p.Kinds, ",")
				}
				title := p.Title
				if !p.Builtin {
					title += "  (" + p.File + ")"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, p.Severity, kinds, title)
			}
			celEngine, err := celpolicy.Load(policyDirs(policies))
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			for _, p := range celEngine.Policies {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, p.Severity, strings.Join(p.Resources, ","), p.Title+"  ("+p.File+")")
			}
			for _, c := range pss.New(level).Checks {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Severity, "pod specs", pssTitle(c))
			}
			for _, t := range tmpllint.Checks {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, t.Severity, "template source", t.Title)
			}
			return tw.Flush()
		},
	}
	addPolicyFlag(cmd, &policies)
	cmd.Flags().StringVar(&pssLevel, "pss", string(pss.Restricted), "Pod Security Standards level: restricted, baseline, or off")
	return cmd
}
