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
	"os"

	"github.com/pkg/errors"
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
		Verifiers: DefaultVerifiers,
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
		return c, errors.Wrap(err, "reading config file")
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(&c); err != nil {
		return c, errors.Wrap(err, "parsing config file")
	}

	return c, nil
}

// Config configures the provider
type Config struct {
	// Verifiers is a list of verifiers used to verify image signatures
	Verifiers []Verifier `yaml:"verifiers"`
}

// UnmarshalYAML configures the default verifiers if none are provided
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawConfig Config
	var raw rawConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}

	if len(raw.Verifiers) == 0 {
		raw.Verifiers = DefaultVerifiers
	}

	*c = Config(raw)

	return nil
}

// Verifier verifies an image signature
type Verifier struct {
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
	RekorURL string `yaml:"rekorURL,omitempty"`
}
