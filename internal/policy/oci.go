package policy

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/bundle"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"helm.sh/helm/v4/pkg/registry"
)

// bundleLayerMediaType is the media type OPA's own OCI downloader filters on
// when looking for the bundle tarball among a manifest's layers.
const bundleLayerMediaType = "application/vnd.oci.image.layer.v1.tar+gzip"

func isOCIRef(s string) bool {
	return strings.HasPrefix(s, "oci://")
}

// pullBundle is LoadModules's hook for fetching an oci:// dirs entry,
// overridden in tests so they can inject a fake registry client without
// routing production code through plain HTTP.
var pullBundle = pullOCIBundle

func pullOCIBundle(ref string) (*bundle.Bundle, error) {
	client, err := registry.NewClient()
	if err != nil {
		return nil, fmt.Errorf("creating OCI client: %w", err)
	}
	return pullOCIBundleWith(client, ref)
}

// pullOCIBundleWith is pullOCIBundle with the OCI client injected, so tests
// can point it at a fake registry (e.g. with registry.ClientOptPlainHTTP()).
func pullOCIBundleWith(client *registry.Client, ref string) (*bundle.Bundle, error) {
	result, err := client.Generic().PullGeneric(ref, registry.GenericPullOptions{})
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}

	var layer *ocispec.Descriptor
	for i, d := range result.Descriptors {
		if d.MediaType == bundleLayerMediaType {
			layer = &result.Descriptors[i]
			break
		}
	}
	if layer == nil {
		return nil, fmt.Errorf("pulling %s: no %s layer in the manifest", ref, bundleLayerMediaType)
	}

	data, err := client.Generic().GetDescriptorData(result.MemoryStore, *layer)
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}

	loader := bundle.NewTarballLoaderWithBaseURL(bytes.NewReader(data), "")
	b, err := bundle.NewCustomReader(loader).WithProcessAnnotations(true).Read()
	if err != nil {
		return nil, fmt.Errorf("reading bundle from %s: %w", ref, err)
	}
	return &b, nil
}
