package main

import (
	"fmt"
	"log"
	"strings"
)

// validatePrivateControlStatePath prepares and validates the durable PCL state
// location before restored deny rules can affect admission decisions.
func validatePrivateControlStatePath(path string, policy secretFilePermissionPolicy) error {
	if strings.TrimSpace(path) == "" || policy == secretFilePermissionsOff {
		return nil
	}
	if policy == "" {
		policy = defaultSecretFilePermissionPolicy()
	}

	if err := preparePrivateControlStatePath(path); err != nil {
		if policy == secretFilePermissionsWarn {
			log.Printf("WARNING: private control state path validation failed; continuing because policy=warn: %v", err)
			return nil
		}
		return fmt.Errorf("private control state path validation: %w", err)
	}
	return nil
}
