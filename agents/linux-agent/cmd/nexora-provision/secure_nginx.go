package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

func readlinkAt(dirFD int, name string) (string, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	n, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	runtime.KeepAlive(path)
	runtime.KeepAlive(buf)

	if errno != 0 {
		return "", errno
	}
	if n == uintptr(len(buf)) {
		return "", fmt.Errorf("symbolic link target exceeds limit")
	}
	return string(buf[:n]), nil
}

func symlinkAt(target string, dirFD int, name string) error {
	targetPtr, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINKAT,
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(namePtr)),
	)
	runtime.KeepAlive(targetPtr)
	runtime.KeepAlive(namePtr)

	if errno != 0 {
		return errno
	}
	return nil
}

// nginxInstallState records only objects created by this invocation.
type nginxInstallState struct {
	configCreated   bool
	linkCreated     bool
	linkPreexisting bool
}

// rollbackNginxInstallAt removes only objects recorded as newly created.
// It checks the symlink target before unlinking it.
func rollbackNginxInstallAt(
	availableFD, enabledFD int,
	configName, target string,
	state nginxInstallState,
) error {
	var rollbackErr error
	linkRemoved := !state.linkCreated

	if state.linkCreated {
		current, err := readlinkAt(enabledFD, configName)

		switch {
		case errors.Is(err, syscall.ENOENT):
			// Confirm the absence is durable before removing the target.
			if syncErr := syscall.Fsync(enabledFD); syncErr != nil {
				rollbackErr = errors.Join(
					rollbackErr,
					fmt.Errorf("could not sync enabled directory after confirming link absence: %w", syncErr),
				)
			} else {
				linkRemoved = true
			}

		case err != nil:
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf("could not verify newly-created enabled link: %w", err),
			)

		case current != target:
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf("enabled link changed; refusing rollback"),
			)

		default:
			if unlinkErr := syscall.Unlinkat(enabledFD, configName); unlinkErr != nil {
				if errors.Is(unlinkErr, syscall.ENOENT) {
					if syncErr := syscall.Fsync(enabledFD); syncErr != nil {
						rollbackErr = errors.Join(
							rollbackErr,
							fmt.Errorf("could not sync enabled directory after link disappeared: %w", syncErr),
						)
					} else {
						linkRemoved = true
					}
				} else {
					rollbackErr = errors.Join(
						rollbackErr,
						fmt.Errorf("could not remove newly-created enabled link: %w", unlinkErr),
					)
				}
			} else if syncErr := syscall.Fsync(enabledFD); syncErr != nil {
				// Keep the config if link removal durability is uncertain.
				rollbackErr = errors.Join(
					rollbackErr,
					fmt.Errorf("could not sync enabled directory after rollback: %w", syncErr),
				)
			} else {
				linkRemoved = true
			}
		}
	}

	// Remove the config only after its newly-created link is durably absent.
	// A pre-existing matching link always protects the config.
	if state.configCreated && !state.linkPreexisting && linkRemoved {
		if err := syscall.Unlinkat(availableFD, configName); err != nil &&
			!errors.Is(err, syscall.ENOENT) {
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf("could not remove newly-created config: %w", err),
			)
		} else if err == nil {
			if syncErr := syscall.Fsync(availableFD); syncErr != nil {
				rollbackErr = errors.Join(
					rollbackErr,
					fmt.Errorf("could not sync available directory after rollback: %w", syncErr),
				)
			}
		}
	}

	return rollbackErr
}

// installNginxConfigAt publishes a config without replacing existing content.
func installNginxConfigAt(
	availableFD, enabledFD int,
	configName, target, content string,
	ownerUID, ownerGID int,
) (nginxInstallState, error) {
	var state nginxInstallState

	created, err := writeConfigFileAtTracked(
		availableFD, configName, content, 0644, ownerUID, ownerGID,
	)
	state.configCreated = created
	if err != nil {
		rollbackErr := rollbackNginxInstallAt(
			availableFD, enabledFD, configName, target, state,
		)
		return state, errors.Join(fmt.Errorf("NGINX_CONFIG_CONFLICT: %w", err), rollbackErr)
	}

	existingTarget, err := readlinkAt(enabledFD, configName)
	if err == nil {
		if existingTarget != target {
			rollbackErr := rollbackNginxInstallAt(
				availableFD, enabledFD, configName, target, state,
			)
			return state, errors.Join(
				fmt.Errorf("NGINX_CONFIG_CONFLICT: enabled site points elsewhere"),
				rollbackErr,
			)
		}
		state.linkPreexisting = true
		return state, nil
	}
	if !errors.Is(err, syscall.ENOENT) {
		rollbackErr := rollbackNginxInstallAt(
			availableFD, enabledFD, configName, target, state,
		)
		return state, errors.Join(
			fmt.Errorf("NGINX_CONFIG_CONFLICT: enabled site path is not a safe symbolic link"),
			rollbackErr,
		)
	}

	if err := symlinkAt(target, enabledFD, configName); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			existingTarget, readErr := readlinkAt(enabledFD, configName)
			if readErr == nil && existingTarget == target {
				state.linkPreexisting = true
				return state, nil
			}
			rollbackErr := rollbackNginxInstallAt(
				availableFD, enabledFD, configName, target, state,
			)
			return state, errors.Join(
				fmt.Errorf("NGINX_CONFIG_CONFLICT: enabled site appeared concurrently"),
				rollbackErr,
			)
		}
		rollbackErr := rollbackNginxInstallAt(
			availableFD, enabledFD, configName, target, state,
		)
		return state, errors.Join(
			fmt.Errorf("NGINX_CONFIG_FAILED: unable to enable site"),
			rollbackErr,
		)
	}

	state.linkCreated = true
	if err := syscall.Fsync(enabledFD); err != nil {
		rollbackErr := rollbackNginxInstallAt(
			availableFD, enabledFD, configName, target, state,
		)
		return state, errors.Join(
			fmt.Errorf("NGINX_CONFIG_FAILED: enabled site directory sync failed"),
			rollbackErr,
		)
	}

	return state, nil
}
