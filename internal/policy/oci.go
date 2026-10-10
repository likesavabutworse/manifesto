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

// VerifyOptions configures signature verification for oci:// policy bundles.
// The zero value means unauthenticated: a bundle with no .signatures.json is
// trusted as-is, and one that does have a signature fails.
// OPA's bundle reader refuses a signed bundle when no verification key is
// configuredw
type VerifyOptions struct {
	PublicKey string // PEM-encoded public key
	Algorithm string // JWS algorithm, e.g. "RS256"; defaults to opa build's own default (RS256) when PublicKey is set
}

// pullBundle is LoadModules's hook for fetching an oci:// dirs entry,
// overridden in tests so they can inject a fake registry client without
// routing production code through plain HTTP.
var pullBundle = pullOCIBundle

func pullOCIBundle(ref string, verify VerifyOptions) (*bundle.Bundle, error) {
	client, err := registry.NewClient()
	if err != nil {
		return nil, fmt.Errorf("creating OCI client: %w", err)
	}
	return pullOCIBundleWith(client, ref, verify)
}

// pullOCIBundleWith is pullOCIBundle with the OCI client injected, so tests
// can point it at a fake registry (e.g. with registry.ClientOptPlainHTTP()).
func pullOCIBundleWith(client *registry.Client, ref string, verify VerifyOptions) (*bundle.Bundle, error) {
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
	reader := bundle.NewCustomReader(loader).WithProcessAnnotations(true)
	if verify.PublicKey != "" {
		alg := verify.Algorithm
		if alg == "" {
			alg = "RS256"
		}
		// "default" matches the key ID `opa build --signing-key` uses when
		// --signing-key-id isn't passed
		const defaultKeyID = "default"
		vc := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{
			defaultKeyID: {Key: verify.PublicKey, Algorithm: alg},
		}, defaultKeyID, "", nil)
		reader = reader.WithBundleVerificationConfig(vc)
	}
	b, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading bundle from %s: %w", ref, err)
	}
	return &b, nil
}
