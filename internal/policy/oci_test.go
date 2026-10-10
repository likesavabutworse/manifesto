package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"helm.sh/helm/v4/pkg/registry"
)

func TestIsOCIRef(t *testing.T) {
	cases := map[string]bool{
		"oci://registry.example.com/policies:latest": true,
		"./policies":    false,
		"/abs/policies": false,
	}
	for ref, want := range cases {
		if got := isOCIRef(ref); got != want {
			t.Errorf("isOCIRef(%q) = %v, want %v", ref, got, want)
		}
	}
}

// buildBundleTarGz builds a minimal, uncompressed-content tar.gz matching
// what `opa build` produces, containing only the given .rego files
// (path -> source). OPA's own test helper for this
// (internal/file/archive.MustWriteTarGz) lives in an `internal` package of
// a different module, so it isn't importable here.
func buildBundleTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: strings.TrimPrefix(path, "/"),
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing tar header for %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("writing tar content for %s: %v", path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}
	return buf.Bytes()
}

// fakeOCIRegistry serves just enough of the OCI distribution spec for
// client.Generic().PullGeneric to pull a single-layer bundle artifact: HEAD
// and GET on the manifest, and GET on its blobs. OPA's own OCI test
// harness (v1/download/testharness.go) is unexported and not reusable
// outside its module, hence this bespoke fixture.
func fakeOCIRegistry(t *testing.T, repo, tag string, layer []byte) *httptest.Server {
	t.Helper()

	layerDigest := digest.FromBytes(layer)
	config := []byte("{}")
	configDigest := digest.FromBytes(config)

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    configDigest,
			Size:      int64(len(config)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: bundleLayerMediaType,
				Digest:    layerDigest,
				Size:      int64(len(layer)),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshaling manifest: %v", err)
	}
	manifestDigest := digest.FromBytes(manifestBytes)

	blobs := map[string][]byte{
		configDigest.String(): config,
		layerDigest.String():  layer,
	}

	manifestPath := fmt.Sprintf("/v2/%s/manifests/%s", repo, tag)
	manifestByDigestPath := fmt.Sprintf("/v2/%s/manifests/%s", repo, manifestDigest.String())

	mux := http.NewServeMux()
	serveManifest := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", manifestDigest.String())
		w.Header().Set("Content-Length", strconv.Itoa(len(manifestBytes)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(manifestBytes)
	}
	mux.HandleFunc(manifestPath, serveManifest)
	mux.HandleFunc(manifestByDigestPath, serveManifest)

	mux.HandleFunc(fmt.Sprintf("/v2/%s/blobs/", repo), func(w http.ResponseWriter, r *http.Request) {
		d := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/v2/%s/blobs/", repo))
		b, ok := blobs[d]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	})

	return httptest.NewServer(mux)
}

func TestPullOCIBundle(t *testing.T) {
	rego := `package manifesto.oci_example

# METADATA
# title: OCI example
# custom:
#   severity: medium
deny contains msg if {
	msg := "from an OCI bundle"
}
`
	layer := buildBundleTarGz(t, map[string]string{"policy.rego": rego})

	srv := fakeOCIRegistry(t, "policies", "v1", layer)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := registry.NewClient(registry.ClientOptPlainHTTP())
	if err != nil {
		t.Fatalf("creating registry client: %v", err)
	}

	b, err := pullOCIBundleWith(client, "oci://"+host+"/policies:v1")
	if err != nil {
		t.Fatalf("pullOCIBundleWith: %v", err)
	}
	if len(b.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(b.Modules))
	}
	if got := b.Modules[0].Parsed.Package.Path.String(); got != "data.manifesto.oci_example" {
		t.Errorf("module package = %q", got)
	}
}

func TestLoadModulesOCI(t *testing.T) {
	rego := `package manifesto.oci_example

deny contains msg if {
	msg := "from an OCI bundle"
}
`
	layer := buildBundleTarGz(t, map[string]string{"policy.rego": rego})
	srv := fakeOCIRegistry(t, "policies", "v1", layer)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	client, err := registry.NewClient(registry.ClientOptPlainHTTP())
	if err != nil {
		t.Fatalf("creating registry client: %v", err)
	}

	old := pullBundle
	pullBundle = func(ref string) (*bundle.Bundle, error) {
		return pullOCIBundleWith(client, ref)
	}
	defer func() { pullBundle = old }()

	ref := "oci://" + host + "/policies:v1"
	modules, builtin, err := LoadModules([]string{ref}, true)
	if err != nil {
		t.Fatalf("LoadModules: %v", err)
	}
	var found *ast.Module
	for name, m := range modules {
		if !builtin[name] && m.Package.Path.String() == "data.manifesto.oci_example" {
			found = m
		}
	}
	if found == nil {
		t.Fatalf("oci:// module not merged into LoadModules output: %v", modules)
	}
}
