package main

import (
        "crypto/rand"
        "encoding/hex"
        "errors"
        "fmt"
        "io"
        "os"
        "syscall"
)

const (
        fmQuarantineRoot  = ".nexora-file-manager-trash"
        fmDeleteMaxDepth  = 64
        fmDeleteMaxItems  = 100000
        fmDeleteMaxPasses = 8
)

func fmPrivateDirectoryAt(parentFD int, name string) (int, error) {
        err := syscall.Mkdirat(parentFD, name, 0700)
        if err != nil && !errors.Is(err, syscall.EEXIST) {
                return -1, err
        }

        fd, err := syscall.Openat(
                parentFD,
                name,
                syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
                0,
        )
        if err != nil {
                return -1, err
        }

        var st syscall.Stat_t
        if err := syscall.Fstat(fd, &st); err != nil {
                syscall.Close(fd)
                return -1, err
        }

        if st.Uid != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
                syscall.Close(fd)
                return -1, fmt.Errorf("quarantine directory is not root-owned")
        }

        if err := syscall.Fchmod(fd, 0700); err != nil {
                syscall.Close(fd)
                return -1, err
        }

        return fd, nil
}

func openFileManagerQuarantine(username string) (int, error) {
        if !usernamePattern.MatchString(username) {
                return -1, fmt.Errorf("invalid account name")
        }

        homeFD, err := syscall.Open(
                "/home",
                syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
                0,
        )
        if err != nil {
                return -1, err
        }
        defer syscall.Close(homeFD)

        var homeStat syscall.Stat_t
        if err := syscall.Fstat(homeFD, &homeStat); err != nil {
                return -1, err
        }

        if homeStat.Uid != 0 ||
                homeStat.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
                homeStat.Mode&0022 != 0 {
                return -1, fmt.Errorf("/home is not a trusted root-owned directory")
        }

        rootFD, err := fmPrivateDirectoryAt(homeFD, fmQuarantineRoot)
        if err != nil {
                return -1, err
        }

        accountFD, err := fmPrivateDirectoryAt(rootFD, username)
        syscall.Close(rootFD)
        if err != nil {
                return -1, err
        }

        return accountFD, nil
}

func fmCheckSameDevice(rootFD, quarantineFD int) error {
        var rootStat, quarantineStat syscall.Stat_t

        if err := syscall.Fstat(rootFD, &rootStat); err != nil {
                return err
        }
        if err := syscall.Fstat(quarantineFD, &quarantineStat); err != nil {
                return err
        }

        if rootStat.Dev != quarantineStat.Dev {
                return fmt.Errorf("document root and quarantine must be on the same filesystem")
        }

        return nil
}

func fmUniqueQuarantineName() (string, error) {
        var random [16]byte
        if _, err := rand.Read(random[:]); err != nil {
                return "", err
        }
        return ".delete-" + hex.EncodeToString(random[:]), nil
}

func fmMoveToQuarantine(sourceFD int, sourceName string, quarantineFD int) (string, error) {
        before, err := fmInspect(sourceFD, sourceName)
        if err != nil {
                return "", err
        }

        for attempt := 0; attempt < 5; attempt++ {
                targetName, err := fmUniqueQuarantineName()
                if err != nil {
                        return "", err
                }

                err = fmRenameat2(
                        sourceFD,
                        sourceName,
                        quarantineFD,
                        targetName,
                        fmRenameNoReplace,
                )
                if errors.Is(err, syscall.EEXIST) {
                        continue
                }
                if err != nil {
                        return "", err
                }

                after, inspectErr := fmInspect(quarantineFD, targetName)
                if inspectErr == nil && sameInode(before, after) {
                        return targetName, nil
                }

                restoreErr := fmRenameat2(
                        quarantineFD,
                        targetName,
                        sourceFD,
                        sourceName,
                        fmRenameNoReplace,
                )

                if restoreErr != nil {
                        return "", fmt.Errorf(
                                "moved item could not be verified and restoration failed; item retained in protected quarantine",
                        )
                }

                if inspectErr != nil {
                        return "", fmt.Errorf("unable to verify quarantined item: %w", inspectErr)
                }

                return "", fmt.Errorf("quarantined item inode did not match the selected item")
        }

        return "", fmt.Errorf("unable to allocate a unique quarantine name")
}

func fmRemoveQuarantinedEntry(
        quarantineFD int,
        name string,
        depth int,
        itemCount *int,
) error {
        if depth > fmDeleteMaxDepth {
                return fmt.Errorf("maximum deletion depth exceeded")
        }

        info, err := fmInspect(quarantineFD, name)
        if errors.Is(err, syscall.ENOENT) {
                return nil
        }
        if err != nil {
                return err
        }

        // Non-directory entries (regular files, symlinks) are leaf entries: they
        // are unlinked in place and never recursed into, so a filesystem-boundary
        // check does not apply to them. On filesystems such as overlayfs the
        // kernel may report a different st_dev for a symlink than for the
        // directory that contains it; applying the boundary check to leaves would
        // make leaf deletion fail spuriously on such filesystems. The boundary
        // check below guards the only path that actually crosses a filesystem
        // boundary: a recursive descent into a subdirectory.
        if info.Mode&syscall.S_IFMT != syscall.S_IFDIR {
                return fmUnlinkat(quarantineFD, name, 0)
        }

        // Never recursively descend into a directory on a different filesystem.
        var quarantineStat syscall.Stat_t
        if err := syscall.Fstat(quarantineFD, &quarantineStat); err != nil {
                return err
        }
        if info.Dev != quarantineStat.Dev {
                return fmt.Errorf("filesystem boundary detected; item retained in quarantine")
        }

        for pass := 0; pass < fmDeleteMaxPasses; pass++ {
                dirFD, err := syscall.Openat(
                        quarantineFD,
                        name,
                        syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
                        0,
                )
                if errors.Is(err, syscall.ENOENT) {
                        return nil
                }
                if err != nil {
                        return err
                }

                var openedStat syscall.Stat_t
                if err := syscall.Fstat(dirFD, &openedStat); err != nil {
                        syscall.Close(dirFD)
                        return err
                }

                if openedStat.Dev != info.Dev ||
                        openedStat.Dev != quarantineStat.Dev ||
                        openedStat.Ino != info.Ino {
                        syscall.Close(dirFD)
                        return fmt.Errorf("quarantined directory identity or filesystem boundary changed")
                }

                dir := os.NewFile(uintptr(dirFD), "nexora-quarantine-directory")
                var readErr error

                for {
                        entries, err := dir.ReadDir(256)

                        for _, entry := range entries {
                                *itemCount++
                                if *itemCount > fmDeleteMaxItems {
                                        dir.Close()
                                        return fmt.Errorf("maximum deletion item count exceeded")
                                }

                                childName := entry.Name()

                                movedName, moveErr := fmMoveToQuarantine(
                                        int(dir.Fd()),
                                        childName,
                                        quarantineFD,
                                )

                                if errors.Is(moveErr, syscall.ENOENT) {
                                        continue
                                }
                                if moveErr != nil {
                                        dir.Close()
                                        return moveErr
                                }

                                if removeErr := fmRemoveQuarantinedEntry(
                                        quarantineFD,
                                        movedName,
                                        depth+1,
                                        itemCount,
                                ); removeErr != nil {
                                        dir.Close()
                                        return removeErr
                                }
                        }

                        if errors.Is(err, io.EOF) {
                                break
                        }
                        if err != nil {
                                readErr = err
                                break
                        }
                        if len(entries) == 0 {
                                break
                        }
                }

                dir.Close()

                if readErr != nil {
                        return readErr
                }

                err = fmUnlinkat(quarantineFD, name, fmAtRemovedir)
                if err == nil || errors.Is(err, syscall.ENOENT) {
                        return nil
                }

                if !errors.Is(err, syscall.ENOTEMPTY) &&
                        !errors.Is(err, syscall.EEXIST) {
                        return err
                }
        }

        return fmt.Errorf("directory remained active during deletion; remaining data retained in protected quarantine")
}

func secureFileManagerDelete(rootFD, quarantineFD int, path string) error {
        if quarantineFD < 0 {
                return fmt.Errorf("DELETE_FAILED: protected quarantine is unavailable")
        }

        if err := fmCheckSameDevice(rootFD, quarantineFD); err != nil {
                return fmt.Errorf("DELETE_FAILED: %w", err)
        }

        parentFD, name, err := fmParent(rootFD, path)
        if err != nil {
                return err
        }
        defer syscall.Close(parentFD)

        _, err = fmInspect(parentFD, name)
        if errors.Is(err, syscall.ENOENT) {
                return fmt.Errorf("FILE_NOT_FOUND: selected item does not exist")
        }
        if err != nil {
                return fmt.Errorf("DELETE_FAILED: unable to inspect selected item")
        }

        quarantineName, err := fmMoveToQuarantine(parentFD, name, quarantineFD)
        if err != nil {
                return fmt.Errorf("DELETE_FAILED: unable to quarantine selected item: %w", err)
        }

        itemCount := 0
        if err := fmRemoveQuarantinedEntry(
                quarantineFD,
                quarantineName,
                0,
                &itemCount,
        ); err != nil {
                return fmt.Errorf("DELETE_FAILED: item retained in protected quarantine: %w", err)
        }

        return nil
}
