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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/minio/pkg/wildcard"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
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

				metadata, err := verifyImageSignatures(ctx, key, v.Verifiers)
				if err != nil {
					fmt.Printf("error verifying %s: %v\n", key, err)
					result.Error = err.Error()
				}

				result.Value = metadata

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

type checkedMetadata struct {
	Signatures   []payload.SimpleContainerImage `json:"signatures"`
	Attestations []in_toto.Statement            `json:"attestations"`
}

func verifyImageSignatures(ctx context.Context, key string, verifiers []Verifier) (*checkedMetadata, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("no verifiers provided for: %s", key)
	}

	for _, o := range verifiers {
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
			var rekorClient *rekorclient.Rekor
			rekorClient, err = rekor.NewClient(o.Options.RekorURL)
			if err != nil {
				return nil, fmt.Errorf("creating rekor client: %v", err)
			}
			co.RekorClient = rekorClient
			fmt.Printf("error using rekor url %s to verify %s\n", o.Options.RekorURL, key)
		}
		if o.Options.Key != "" {
			var pubKey signature.Verifier
			pubKey, err = sigs.PublicKeyFromKeyRef(ctx, o.Options.Key)
			if err != nil {
				return nil, fmt.Errorf("error getting public key from key reference: %v", err)
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
			return nil, fmt.Errorf("error parsing image reference: %v", err)
		}

		metadata := &checkedMetadata{}
		if contains(o.Verifies, "imageSignature") {
			checkedSignatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
			if err != nil {
				return nil, fmt.Errorf("error verifying image signatures: %v", err)
			}

			if co.RekorClient != nil && !bundleVerified {
				return nil, fmt.Errorf("no valid signatures found for %s: %v", key, err)
			}

			if len(checkedSignatures) == 0 {
				return nil, fmt.Errorf("no valid signatures found for %s", key)
			}

			metadata.Signatures, err = formatSignaturePayloads(checkedSignatures)
			if err != nil {
				return nil, fmt.Errorf("error formatting signature payload: %v", err)
			}

			fmt.Println("signature verified for: ", key)
			fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)
		}
		if contains(o.Verifies, "attestation") {
			fmt.Println("Verifying Attestations for image: ", key)

			checkedAttestations, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, co)
			if err != nil {
				return nil, fmt.Errorf("error verifying attestations: %v", err)
			}
			if co.RekorClient != nil && !bundleVerified {
				return nil, fmt.Errorf("no valid attestations found for: %s", key)
			}

			AttestationPayloads, err := formatAttestations(checkedAttestations)
			if err != nil {
				return nil, fmt.Errorf("formatAttestations: %v", err)
			}

			metadata.Attestations = AttestationPayloads

			fmt.Println("attestation verified for: ", key)
			fmt.Printf("%d number of valid attestations found for %s, found attestations: %v\n", len(checkedAttestations), key, checkedAttestations)
		}

		return metadata, nil
	}

	return nil, fmt.Errorf("no verifier found for: %s", key)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// formatAttestations takes the payload within an Attestation and base64 decodes it, returning it as an in-toto statement
func formatAttestations(verifiedAttestations []oci.Signature) ([]in_toto.Statement, error) {

	decodedAttestations := make([]in_toto.Statement, len(verifiedAttestations))

	for i, att := range verifiedAttestations {
		p, err := att.Payload()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching payload: %v", err)
			return nil, err
		}

		var pm map[string]interface{}
		json.Unmarshal(p, &pm)

		payload := strings.Trim(fmt.Sprintf("%v", pm["payload"]), "\"")

		statementRaw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decoding attestation payload: %v", err)
		}

		var statement in_toto.Statement
		if err := json.Unmarshal(statementRaw, &statement); err != nil {
			return nil, err
		}

		decodedAttestations[i] = statement
	}

	return decodedAttestations, nil

}

// formatPayload converts the signature into a payload to be sent back to gatekeeper
func formatSignaturePayloads(verifiedSignatures []oci.Signature) ([]payload.SimpleContainerImage, error) {

	var outputKeys []payload.SimpleContainerImage

	for _, sig := range verifiedSignatures {
		p, err := sig.Payload()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching payload: %v", err)
			return nil, err
		}

		ss := payload.SimpleContainerImage{}
		if err := json.Unmarshal(p, &ss); err != nil {
			fmt.Println("error decoding the payload:", err.Error())
			return nil, err
		}

		if cert, err := sig.Cert(); err == nil && cert != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Subject"] = sigs.CertSubject(cert)
			if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
				ss.Optional["Issuer"] = issuerURL
			}
		}
		if bundle, err := sig.Bundle(); err == nil && bundle != nil {
			if ss.Optional == nil {
				ss.Optional = make(map[string]interface{})
			}
			ss.Optional["Bundle"] = bundle
		}

		outputKeys = append(outputKeys, ss)
	}

	return outputKeys, nil
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
