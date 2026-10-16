package shellport

import (
	"os"

	"golang.org/x/sys/unix"
)

// O_PATH supports fstat and openat without requiring directory-list access.
const stateDirectoryAccess = unix.O_PATH

// Linux POSIX ACL named-user/group permissions are constrained by the ACL
// mask, which is reflected in the group mode bits checked on the descriptor.
func checkStateACL(f *os.File, private bool) error { return nil }
