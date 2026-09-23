//go:build windows

package main

import (
	"fmt"
	"runtime"
)

func preparePrivateControlStatePath(string) error {
	return fmt.Errorf("private control state ownership validation is unsupported on %s", runtime.GOOS)
}

func syncPrivateControlStateDirectory(string) error {
	// Stateful PCL revocation is rejected at startup on Windows. This keeps
	// direct unit-test helpers usable without claiming directory durability.
	return nil
}

func validatePrivateControlStateDurability() error {
	return fmt.Errorf("durable private control revocation is unsupported on %s because directory sync is unavailable", runtime.GOOS)
}
