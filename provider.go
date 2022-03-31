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
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
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
		for _, image := range providerRequest.Request.Keys {
			result := externaldata.Item{
				Key: image,
			}
			fmt.Printf("checking image: %s\n", image)
			signatures, err := verify(ctx, image, cfg.Verifiers)
			if err != nil {
				fmt.Printf("error when verifying %s: %v", image, err)
				result.Error = err.Error()
			}
			fmt.Printf("found %d signatures for %s\n", len(signatures), image)
			result.Value = &Value{
				Signatures: signatures,
			}

			results = append(results, result)
		}

		sendResponse(&results, "", w)
	}
}

// verify verifies an image with a list of verifiers and returns a list of
// signatures
func verify(ctx context.Context, image string, verifiers []Verifier) ([]Signature, error) {
	var signatures []Signature

	sl, h, err := signaturesFromImage(ctx, image)
	if err != nil {
		return signatures, errors.Wrap(err, "getting signatures from image")
	}

	for _, sig := range sl {
		p, err := payloadFromSignature(sig)
		if err != nil {
			return signatures, errors.Wrap(err, "getting payload from signature")
		}

		resultSignature := Signature{
			Payload: p,
		}

		for _, verifier := range verifiers {
			verified, publicKey, err := verifySignature(ctx, sig, h, verifier)
			if err != nil {
				return signatures, errors.Wrap(err, "verifying signature")
			}
			if !verified {
				continue
			}

			resultSignature.Verified = true
			resultSignature.ID = &Identity{
				Key: publicKey,
			}

			if cert, err := sig.Cert(); err == nil && cert != nil {
				resultSignature.ID.Subject = sigs.CertSubject(cert)
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					resultSignature.ID.Issuer = issuerURL
				}
			}

			break
		}

		signatures = append(signatures, resultSignature)
	}

	return signatures, nil
}

// signaturesFromImage returns the signatures for the provided image reference
func signaturesFromImage(ctx context.Context, image string) (sl []oci.Signature, h v1.Hash, err error) {
	ro := options.RegistryOptions{}
	ociremoteOpts, err := ro.ClientOpts(ctx)
	if err != nil {
		return sl, h, errors.Wrap(err, "creating registry client options")
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return sl, h, errors.Wrap(err, "parsing image reference")
	}

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	if err != nil {
		return sl, h, errors.Wrap(err, "retrieving signed entity")
	}

	h, err = se.(interface{ Digest() (v1.Hash, error) }).Digest()
	if err != nil {
		return sl, h, errors.Wrap(err, "getting digest from signed entity")
	}

	signatures, err := se.Signatures()
	if err != nil {
		return sl, h, errors.Wrap(err, "getting signatures from signed entity")
	}

	sl, err = signatures.Get()
	if err != nil {
		return sl, h, errors.Wrap(err, "getting signatures")
	}

	return sl, h, nil
}

// verifySignature verifies the provided signature with a specific verifier
func verifySignature(ctx context.Context, sig oci.Signature, h v1.Hash, verifier Verifier) (verified bool, publicKey []byte, err error) {
	co := &cosign.CheckOpts{
		RootCerts:     fulcio.GetRoots(),
		ClaimVerifier: cosign.SimpleClaimVerifier,
	}

	if rekorURL := verifier.Options.RekorURL; rekorURL != "" {
		var rekorClient *rekorclient.Rekor
		rekorClient, err = rekor.NewClient(rekorURL)
		if err != nil {
			return verified, publicKey, errors.Wrap(err, "creating rekor client")
		}
		co.RekorClient = rekorClient
	}

	if key := verifier.Options.Key; key != "" {
		var k signature.Verifier

		if strings.HasPrefix(key, "-----BEGIN PUBLIC KEY-----") {
			var ed *ecdsa.PublicKey
			ed, err = cosign.PemToECDSAKey([]byte(key))
			if err != nil {
				return verified, publicKey, errors.Wrap(err, "converting PEM to ECDSA")
			}

			k, err = signature.LoadECDSAVerifier(ed, crypto.SHA256)
			if err != nil {
				return verified, publicKey, errors.Wrap(err, "loading ecdsa verifier")
			}
		} else {
			k, err = sigs.PublicKeyFromKeyRef(ctx, key)
			if err != nil {
				return verified, publicKey, errors.Wrap(err, "getting public key from key ref")
			}
		}

		if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
			defer pkcs11Key.Close()
		}

		publicKey, err = sigs.PublicKeyPem(k)
		if err != nil {
			return verified, publicKey, errors.Wrap(err, "getting public key PEM")
		}

		co.SigVerifier = k
	}

	_, err = cosign.VerifyImageSignature(ctx, sig, h, co)
	if err == nil {
		verified = true
	}

	return verified, publicKey, nil
}

// payloadFromSignature extracts the payload from a signature
func payloadFromSignature(sig oci.Signature) (payload.SimpleContainerImage, error) {
	ss := payload.SimpleContainerImage{}

	p, err := sig.Payload()
	if err != nil {
		return ss, errors.Wrap(err, "getting payload from signature")
	}

	if err := json.Unmarshal(p, &ss); err != nil {
		return ss, errors.Wrap(err, "unmarshaling payload json")
	}

	return ss, nil
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
