package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseSecretFilePermissionPolicy(t *testing.T) {
	for _, test := range []struct {
		value string
		want  secretFilePermissionPolicy
	}{
		{"required", secretFilePermissionsRequired},
		{"WARN", secretFilePermissionsWarn},
		{"off", secretFilePermissionsOff},
		{"", defaultSecretFilePermissionPolicy()},
	} {
		got, err := parseSecretFilePermissionPolicy(test.value)
		if err != nil || got != test.want {
			t.Fatalf("parseSecretFilePermissionPolicy(%q) = %q, %v; want %q, nil", test.value, got, err, test.want)
		}
	}
	if _, err := parseSecretFilePermissionPolicy("permissive"); err == nil {
		t.Fatal("accepted an invalid secret file permission policy")
	}
}

func TestValidateSecretFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == "windows" {
		if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsRequired); err == nil {
			t.Fatal("required policy unexpectedly accepted an unverifiable Windows ACL")
		}
		if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsWarn); err != nil {
			t.Fatalf("warn policy rejected an unverifiable Windows ACL: %v", err)
		}
		return
	}

	if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsRequired); err != nil {
		t.Fatalf("required policy rejected mode 0600: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsRequired); err == nil {
		t.Fatal("required policy accepted a group-readable secret")
	}
	if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsWarn); err != nil {
		t.Fatalf("warn policy rejected a group-readable secret: %v", err)
	}
	if err := validateSecretFilePermissions(path, "test secret", secretFilePermissionsOff); err != nil {
		t.Fatalf("off policy rejected a secret: %v", err)
	}
	if err := validateSecretFilePermissions(t.TempDir(), "test secret", secretFilePermissionsRequired); err == nil {
		t.Fatal("required policy accepted a directory")
	}
}
