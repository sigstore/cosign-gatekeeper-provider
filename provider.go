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
	sigs "github.com/sigstore/cosign/pkg/signature"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature"
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

			var hasImageVerifier bool

			for _, v := range cfg.ImageVerifiers {
				if !wildcard.Match(v.Image, key) {
					continue
				}

				hasImageVerifier = true

				if err := verifyImageSignatures(ctx, key, v.Verifiers); err != nil {
					fmt.Printf("error verifying %s: %v\n", key, err)
					result.Error = err.Error()
				}

				break
			}

			if !hasImageVerifier {
				result.Error = fmt.Sprintf("no image verifier found for: %s", key)
			}

			results = append(results, result)
		}

		sendResponse(&results, "", w)
	}
}

func verifyImageSignatures(ctx context.Context, key string, verifiers []Verifier) error {
	if len(verifiers) == 0 {
		return fmt.Errorf("no verifiers provided for: %s", key)
	}

	for _, o := range verifiers {
		ro := options.RegistryOptions{}
		ociremoteOpts, err := ro.ClientOpts(ctx)
		if err != nil {
			return err
		}
		co := &cosign.CheckOpts{
			RegistryClientOpts: ociremoteOpts,
			RootCerts:          fulcio.GetRoots(),
		}
		if o.Options.RekorURL != "" {
			var rekorClient *rekorclient.Rekor
			rekorClient, err = rekor.NewClient(o.Options.RekorURL)
			if err != nil {
				return fmt.Errorf("creating rekor client: %v", err)
			}
			co.RekorClient = rekorClient
			fmt.Printf("error using rekor url %s to verify %s\n", o.Options.RekorURL, key)
		}
		if o.Options.Key != "" {
			var pubKey signature.Verifier
			pubKey, err = sigs.PublicKeyFromKeyRef(ctx, o.Options.Key)
			if err != nil {
				return fmt.Errorf("error getting public key from key reference: %v", err)
			}
			pkcs11Key, ok := pubKey.(*pkcs11key.Key)
			if ok {
				defer pkcs11Key.Close()
			}
			co.SigVerifier = pubKey
			fmt.Printf("using key %s to verify %s\n", o.Options.Key, key)
		}

		ref, err := name.ParseReference(key)
		if err != nil {
			return fmt.Errorf("error parsing image reference: %v", err)
		}

		checkedSignatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
		if err != nil {
			return fmt.Errorf("error verifying image signatures: %v", err)
		}

		if co.RekorClient != nil && !bundleVerified {
			return fmt.Errorf("no valid signatures found for %s: %v", key, err)
		}

		if len(checkedSignatures) == 0 {
			return fmt.Errorf("no valid signatures found for %s", key)
		}

		fmt.Println("signature verified for:", key)
		fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)
	}

	return nil
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
