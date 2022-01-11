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

	// DefaultConfig is the configuration used when none is provided
	DefaultConfig = &Config{
		Verifiers: []Verifier{
			{
				Options: DefaultOptions,
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
	// Verifiers is a list of verifiers. The validator will iterate over
	// this list until it finds a verifier that matches the image its
	// validating.
	Verifiers []Verifier `yaml:"verifiers"`
}

// Verifier verifies an image
type Verifier struct {
	// Image is an image reference, either to a specific image or a pattern.
	// Supports '*' and '?' in the pattern string.
	Image string `yaml:"image,omitempty"`

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
