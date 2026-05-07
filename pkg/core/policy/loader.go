// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a LocalPolicyPack from a YAML file, validates it, and
// returns the parsed struct. Returns an error if the file cannot be read,
// parsed, or fails validation.
func LoadFromFile(path string) (*PolicyPack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var pp PolicyPack
	if err := yaml.Unmarshal(raw, &pp); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	if err := pp.Validate(); err != nil {
		return nil, fmt.Errorf("policy: validate %s: %w", path, err)
	}
	return &pp, nil
}
