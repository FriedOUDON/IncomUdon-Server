//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func preparePrivateControlStatePath(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := validatePrivateControlStateDirectory(directory); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("state file must be a regular file")
	}
	if err := requirePrivateControlStateOwner(info, "state file"); err != nil {
		return err
	}
	permissions := info.Mode().Perm()
	if permissions&0o600 != 0o600 {
		return fmt.Errorf("state file must be owner-readable and owner-writable (mode %04o)", permissions)
	}
	if permissions&0o077 != 0 {
		return fmt.Errorf("state file must not grant group or other permissions (mode %04o)", permissions)
	}
	return nil
}

func validatePrivateControlStateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("state directory must be a directory and not a symlink")
	}
	if err := requirePrivateControlStateOwner(info, "state directory"); err != nil {
		return err
	}
	permissions := info.Mode().Perm()
	if permissions&0o700 != 0o700 {
		return fmt.Errorf("state directory must grant its owner read, write, and search permission (mode %04o)", permissions)
	}
	if permissions&0o077 != 0 {
		return fmt.Errorf("state directory must not grant group or other permissions (mode %04o)", permissions)
	}
	return nil
}

func requirePrivateControlStateOwner(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect %s owner", label)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s owner UID %d does not match Relay UID %d", label, stat.Uid, os.Geteuid())
	}
	return nil
}

func syncPrivateControlStateDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func validatePrivateControlStateDurability() error {
	return nil
}
