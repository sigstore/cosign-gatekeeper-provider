// Copyright The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/minio/pkg/wildcard"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

var (
	configFile = flag.String("config-file", "", "path to a configuration file")
)

func main() {
	flag.Parse()

	cfg, err := LoadConfig(*configFile)
	if err != nil {
		panic(err)
	}

	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate(cfg))

	if err := http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func validate(cfg *Config) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		// only accept POST requests
		if req.Method != http.MethodPost {
			sendResponse(nil, "only POST is allowed", w)
			return
		}

		// read request body
		requestBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
			return
		}

		// parse request body
		var providerRequest externaldata.ProviderRequest
		err = json.Unmarshal(requestBody, &providerRequest)
		if err != nil {
			sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
			return
		}

		results := make([]externaldata.Item, 0)

		ctx := req.Context()

		// iterate over all keys
		for _, key := range providerRequest.Request.Keys {
			result := externaldata.Item{
				Key: key,
			}
			fmt.Println("verify signature for:", key)
			metadata, err := verifyImageSignatures(ctx, key, cfg.Verifiers)
			if err != nil {
				result.Error = err.Error()
			}
			result.Value = metadata
			results = append(results, result)
		}

		sendResponse(&results, "", w)
	}
}

type CheckedMetadata struct {
	ImageSignatures       []oci.Signature `json:"imageSignatures"`
	AttestationSignatures []oci.Signature `json:"AttestationSignatures"`
}

func verifyImageSignatures(ctx context.Context, key string, verifiers []Verifier) (*CheckedMetadata, error) {
	for _, o := range verifiers {
		if !wildcard.Match(o.Image, key) {
			continue
		}

		ro := options.RegistryOptions{}
		ociremoteOpts, err := ro.ClientOpts(ctx)
		if err != nil {
			return nil, err
		}
		co := &cosign.CheckOpts{
			RegistryClientOpts: ociremoteOpts,
			RootCerts:          fulcio.GetRoots(),
		}
		if o.Options.RekorURL != "" {
			rekorClient, err := rekor.NewClient(o.Options.RekorURL)
			if err != nil {
				return nil, fmt.Errorf("rekor.NewClient: %v", err)
			}
			co.RekorClient = rekorClient
		}
		if o.Options.Key != "" {
			pubKey, err := sigs.PublicKeyFromKeyRef(ctx, o.Options.Key)
			if err != nil {
				return nil, fmt.Errorf("PublicKeyFromKeyRef: %v", err)
			}
			pkcs11Key, ok := pubKey.(*pkcs11key.Key)
			if ok {
				defer pkcs11Key.Close()
			}
			co.SigVerifier = pubKey
		}

		ref, err := name.ParseReference(key)
		if err != nil {
			return nil, fmt.Errorf("ParseReference: %v", err)
		}

		var metadata *CheckedMetadata

		checkedSignatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
		if err != nil {
			return nil, fmt.Errorf("VerifyImageSignatures: %v", err)
		}

		if co.RekorClient != nil && !bundleVerified {
			return nil, fmt.Errorf("no valid signatures found for %s: %v", key, err)
		}

		if len(checkedSignatures) == 0 {
			return nil, fmt.Errorf("no valid signatures found for %s", key)
		}

		metadata.ImageSignatures = checkedSignatures

		fmt.Println("signature verified for: ", key)
		fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)

		if o.AttestationPresent {
			fmt.Println("Verifying Attestations for image: ", key)

			checkedAttestations, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, co)
			if err != nil {
				return nil, fmt.Errorf("VerifyImageAttestations: %v", err)
			}
			if !bundleVerified {
				return nil, fmt.Errorf("no valid attestations found for: %s", key)
			}

			metadata.AttestationSignatures = checkedAttestations

			fmt.Println("attestation verified for: ", key)
			fmt.Printf("%d number of valid attestations found for %s, found attestations: %v\n", len(checkedAttestations), key, checkedAttestations)
		}

		return metadata, nil
	}

	return nil, fmt.Errorf("no verifier found for: %s", key)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}
