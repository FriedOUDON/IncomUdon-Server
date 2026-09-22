//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func startPrivateControlUDSListener(config privateControlConfig) (net.Listener, error) {
	socketPath := filepath.Clean(config.udsSocketPath)
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("private control UDS socket path must be absolute")
	}
	groupID, err := strconv.ParseUint(config.udsSocketGroup, 10, 32)
	if err != nil || groupID == 0 {
		return nil, errors.New("private control UDS socket group must be a non-zero numeric GID")
	}
	parent := filepath.Dir(socketPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect private control UDS directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, errors.New("private control UDS parent must be a directory, not a symlink")
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("private control UDS parent must not be group- or world-writable")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private control UDS parent must be owned by the Relay OS user")
	}
	if existing, err := os.Lstat(socketPath); err == nil {
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("private control UDS path exists and is not a socket")
		}
		existingStat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || existingStat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("private control UDS socket is not owned by the Relay OS user")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale private control UDS socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect private control UDS socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("private control UDS listener: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chown(socketPath, -1, int(groupID)); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set private control UDS socket group: %w", err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set private control UDS socket permissions: %w", err)
	}
	return listener, nil
}

func authenticatePrivateControlUDSConnection(rawConnection net.Conn, policy privateControlPolicy) (net.Conn, string, error) {
	connection, ok := rawConnection.(*net.UnixConn)
	if !ok {
		return nil, "", errors.New("private control UDS listener returned a non-Unix connection")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, "", fmt.Errorf("access private control UDS socket descriptor: %w", err)
	}
	var (
		credentials   *syscall.Ucred
		credentialErr error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, "", fmt.Errorf("read private control UDS peer credentials: %w", err)
	}
	if credentialErr != nil || credentials == nil {
		return nil, "", errors.New("read private control UDS peer credentials")
	}
	serviceID, found := policy.byUID[credentials.Uid]
	if !found {
		return nil, "", errors.New("private control UDS peer UID is not authorized")
	}
	return connection, serviceID, nil
}
