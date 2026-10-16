package shellport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxPrivateStateBytes = 4 << 20

// Resolve operator aliases once, then keep using the checked canonical path.
// In particular, /var and /tmp are normal root-owned aliases on macOS.
func privateStateDirectory(path string) (string, error) {
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("data directory must be a real directory, not a symbolic link")
	}
	path, err = canonicalDirectory(path)
	if err != nil {
		return "", err
	}
	f, err := openStateDirectory(path, true)
	if err != nil {
		return "", err
	}
	f.Close()
	return path, nil
}

// Check every canonical ancestor: a private leaf alone cannot prevent its
// replacement by the owner of a writable parent. A trusted sticky directory
// (such as /tmp) protects children owned by the effective service account.
func openStateDirectory(path string, private bool) (*os.File, error) {
	path, err := canonicalDirectory(path)
	if err != nil {
		return nil, err
	}
	// Traversal and descriptor metadata checks do not require directory listings.
	flags := stateDirectoryAccess | unix.O_DIRECTORY | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i := 0; ; i++ {
		leaf := i == len(parts)
		info, statErr := f.Stat()
		if statErr == nil {
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (int(owner.Uid) != os.Geteuid() && (leaf && private || owner.Uid != 0)) {
				statErr = fmt.Errorf("%s must be owned by the service account%s", f.Name(), ownerSuffix(leaf && private))
			} else if leaf && private && info.Mode().Perm()&0077 != 0 {
				statErr = fmt.Errorf("data directory must be private (chmod 700); review existing state before restarting")
			} else if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				statErr = fmt.Errorf("%s must not be writable by other accounts", f.Name())
			} else {
				statErr = checkStateACL(f, leaf && private)
			}
		}
		if statErr != nil {
			f.Close()
			return nil, statErr
		}
		if leaf {
			return f, nil
		}
		next, openErr := unix.Openat(int(f.Fd()), parts[i], flags|unix.O_NOFOLLOW, 0)
		name := filepath.Join(f.Name(), parts[i])
		f.Close()
		if openErr != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: openErr}
		}
		f = os.NewFile(uintptr(next), name)
	}
}

func ownerSuffix(private bool) string {
	if private {
		return ""
	}
	return " or root"
}

// O_NOFOLLOW and f.Stat bind validation and reading to the same inode.
// O_NONBLOCK ensures a replaced FIFO cannot stall startup before validation.
func readPrivateState(path string) ([]byte, error) {
	dir, err := openStateDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err = validatePrivateStateFile(f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPrivateStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPrivateStateBytes {
		return nil, fmt.Errorf("%s exceeds its supported size", path)
	}
	return data, nil
}

func validatePrivateStateFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be a regular, private file owned by the service account (chmod 600), without symbolic links", f.Name())
	}
	if info.Size() > maxPrivateStateBytes {
		return fmt.Errorf("%s exceeds its supported size", f.Name())
	}
	return checkStateACL(f, true)
}
