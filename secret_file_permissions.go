package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

type secretFilePermissionPolicy string

const (
	secretFilePermissionsRequired secretFilePermissionPolicy = "required"
	secretFilePermissionsWarn     secretFilePermissionPolicy = "warn"
	secretFilePermissionsOff      secretFilePermissionPolicy = "off"
)

func defaultSecretFilePermissionPolicy() secretFilePermissionPolicy {
	if runtime.GOOS == "windows" {
		return secretFilePermissionsWarn
	}
	return secretFilePermissionsRequired
}

func parseSecretFilePermissionPolicy(value string) (secretFilePermissionPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return defaultSecretFilePermissionPolicy(), nil
	case string(secretFilePermissionsRequired):
		return secretFilePermissionsRequired, nil
	case string(secretFilePermissionsWarn):
		return secretFilePermissionsWarn, nil
	case string(secretFilePermissionsOff):
		return secretFilePermissionsOff, nil
	default:
		return "", errors.New("must be required, warn, or off")
	}
}

// validateSecretFilePermissions rejects secret files readable or writable by a
// group or other user. Windows ACL inspection is not portable in this Relay.
func validateSecretFilePermissions(path string, label string, policy secretFilePermissionPolicy) error {
	if strings.TrimSpace(path) == "" || policy == secretFilePermissionsOff {
		return nil
	}
	if policy == "" {
		policy = defaultSecretFilePermissionPolicy()
	}

	var validationErr error
	if runtime.GOOS == "windows" {
		validationErr = errors.New("Windows ACL permissions cannot be validated by this Relay")
	} else {
		info, err := os.Stat(path)
		if err != nil {
			validationErr = fmt.Errorf("inspect file: %w", err)
		} else if !info.Mode().IsRegular() {
			validationErr = errors.New("must be a regular file")
		} else {
			permissions := info.Mode().Perm()
			switch {
			case permissions&0o400 == 0:
				validationErr = errors.New("must be readable by its owner")
			case permissions&0o077 != 0:
				validationErr = fmt.Errorf("must not grant group or other permissions (mode %04o)", permissions)
			}
		}
	}
	if validationErr == nil {
		return nil
	}
	if policy == secretFilePermissionsWarn {
		log.Printf("WARNING: %s permission validation failed; continuing because policy=warn: %v", label, validationErr)
		return nil
	}
	return fmt.Errorf("%s permission validation: %w", label, validationErr)
}
