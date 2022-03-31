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
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var (
	// DefaultOptions are the default verification options
	DefaultOptions = &CheckOptions{
		RekorURL: "https://rekor.sigstore.dev",
	}

	// DefaultVerifiers are the default verifiers for an image
	DefaultVerifiers = []Verifier{
		{
			Options: DefaultOptions,
		},
	}

	// DefaultConfig is the configuration used when none is provided
	DefaultConfig = &Config{
		ImageVerifiers: []ImageVerifier{
			{
				Verifiers: DefaultVerifiers,
			},
		},
	}
)

// LoadConfig loads configuration from a file. If a file isn't provided then it
// returns the default configuration.
func LoadConfig(confFile string) (*Config, error) {
	if confFile == "" {
		return DefaultConfig, nil
	}

	var c *Config

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return c, fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("error parsing config file: %s", err)
	}

	return c, nil
}

// Config configures the provider
type Config struct {
	// ImageVerifiers is a list of image verifiers. An image verifier
	// associates an image reference or pattern with a list of verification
	// options.
	ImageVerifiers []ImageVerifier `yaml:"imageVerifiers"`
}

// ImageVerifier defines a list of verifiers for a specific image reference or
// image reference pattern
type ImageVerifier struct {
	// Image is an image reference, either to a specific image or a pattern.
	// Supports '*' and '?' in the pattern string.
	Image string `yaml:"image,omitempty"`

	// Verifiers is a list of verifiers. The validator ensures the image can
	// be verified by every verifier in the list.
	Verifiers []Verifier `yaml:"verifiers,omitempty"`
}

// UnmarshalYAML sets default options for the image verifier when they aren't
// provided
func (v *ImageVerifier) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawVerifier ImageVerifier
	var raw rawVerifier
	if err := unmarshal(&raw); err != nil {
		return err
	}

	if len(raw.Verifiers) == 0 {
		raw.Verifiers = DefaultVerifiers
	}

	*v = ImageVerifier(raw)

	return nil
}

// Verifier verifies an image
type Verifier struct {
	Verifies []string `yaml:"verifies"`
	// Options defines verification options
	Options *CheckOptions `yaml:"options,omitempty"`
}

// UnmarshalYAML sets default options for the verifier config when they aren't
// provided
func (v *Verifier) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawVerifier Verifier
	var raw rawVerifier
	if err := unmarshal(&raw); err != nil {
		return err
	}

	if raw.Options == nil {
		raw.Options = DefaultOptions
	}

	*v = Verifier(raw)

	return nil
}

// CheckOptions are the options used to verify the signature of an image
type CheckOptions struct {
	// Key is a path to a public key file, KMS URI or Kubernetes Secret
	Key string `yaml:"key,omitempty"`

	// RekorURL is the address of a rekor STL server
	RekorURL string `yaml:"rekor_url,omitempty"`
}
