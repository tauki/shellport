package shellport

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// O_SEARCH allows traversal and descriptor checks without directory-list access.
const stateDirectoryAccess = unix.O_SEARCH

// macOS ACL grants are independent of POSIX mode bits. Query the opened inode
// using fgetattrlist and the sys/attr.h + sys/kauth.h filesec layout. Deny-only
// ACLs (including the usual home-directory delete protection) remain valid.
func checkStateACL(f *os.File, private bool) error {
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	var buf [4096]byte // filesec header plus the kernel's maximum 128 ACEs
	_, _, errno := syscall.Syscall6(syscall.SYS_FGETATTRLIST, f.Fd(), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("cannot check ACL for %s: %w", f.Name(), errno)
	}
	return validateStateACL(buf[:], private, f.Name())
}

func validateStateACL(buf []byte, private bool, name string) error {
	invalid := fmt.Errorf("cannot validate ACL for %s", name)
	if len(buf) < 12 {
		return invalid
	}
	size := int(binary.LittleEndian.Uint32(buf[:4]))
	if size < 12 || size > len(buf) {
		return invalid
	}
	length := int(binary.LittleEndian.Uint32(buf[8:12]))
	if length == 0 {
		return nil
	} // no extended security
	offset := int(int32(binary.LittleEndian.Uint32(buf[4:8]))) + 4
	if offset < 12 || length < 44 || offset > size-length {
		return invalid
	}
	sec := buf[offset : offset+length]
	if binary.LittleEndian.Uint32(sec[:4]) != 0x012cc16d {
		return invalid
	}
	count := binary.LittleEndian.Uint32(sec[36:40])
	if count == ^uint32(0) {
		return nil
	} // KAUTH_FILESEC_NOACL
	if count > 128 || 44+int(count)*24 > len(sec) {
		return invalid
	}
	// Any grant that can replace/modify children, the inode, or its protections
	// is unsafe in an ancestor. Private state also disallows read/search grants.
	var forbidden uint32 = 1<<2 | 1<<4 | 1<<5 | 1<<6 | 1<<8 | 1<<10 | 1<<12 | 1<<13
	if private {
		forbidden |= 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11
	}
	for i := 0; i < int(count); i++ {
		ace := sec[44+i*24 : 44+(i+1)*24]
		flags := binary.LittleEndian.Uint32(ace[16:20])
		rights := binary.LittleEndian.Uint32(ace[20:24])
		if flags&0xf == 1 && rights&forbidden != 0 { // KAUTH_ACE_PERMIT
			return fmt.Errorf("%s has an ACL grant; remove shared state access before restarting", name)
		}
	}
	return nil
}
