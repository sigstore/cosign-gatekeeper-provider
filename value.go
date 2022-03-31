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

import "github.com/sigstore/sigstore/pkg/signature/payload"

// Value is the value returned for each image
type Value struct {
	// Signatures are the signatures on the image
	Signatures []Signature `json:"signatures,omitempty"`
}

// Signature is a signature on an image
type Signature struct {
	// ID holds information about the identity of the signer
	ID *Identity `json:"id,omitempty"`

	// Payload holds the signature payload
	Payload payload.SimpleContainerImage `json:"payload"`

	// Verified indicates whether the signature could be verified
	Verified bool `json:"verified"`
}

// Identity is the identity of the signer
type Identity struct {
	// Issuer holds the URL of the OIDC issuer that verified the signatory's identity.
	// This is populated for "keyless" verification.
	Issuer string `json:"iss,omitempty"`

	// Subject holds the subject identifier that was encoded into the certificate.
	// This is populated for "keyless" verification.
	Subject string `json:"sub,omitempty"`

	// Key holds the PEM encoded public key that was used to verify the
	// signature.
	// This is populated if an explicit key was provided for verification.
	Key []byte `json:"key,omitempty"`
}
