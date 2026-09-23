//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateControlStatePathRequiresRelayPrivateDirectoryAndFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if err := validatePrivateControlStatePath(path, secretFilePermissionsRequired); err != nil {
		t.Fatalf("validate new private state path: %v", err)
	}
	if err := writePrivateControlPersistentState(path, privateControlPersistentState{SchemaVersion: privateControlStateSchemaVersion}); err != nil {
		t.Fatalf("write persistent state: %v", err)
	}
	if err := validatePrivateControlStatePath(path, secretFilePermissionsRequired); err != nil {
		t.Fatalf("validate private state file: %v", err)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateControlStatePath(path, secretFilePermissionsRequired); err == nil {
		t.Fatal("accepted group-readable private control state file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateControlStatePath(path, secretFilePermissionsRequired); err == nil {
		t.Fatal("accepted group-accessible private control state directory")
	}
}
