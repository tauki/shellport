package shellport

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func addStateTestACL(t *testing.T, path, acl string) {
	t.Cleanup(func() {
		if output, err := exec.Command("/bin/chmod", "-a", acl, path).CombinedOutput(); err != nil {
			t.Errorf("remove test ACL: %v %s", err, output)
		}
	})
	t.Helper()
	if output, err := exec.Command("/bin/chmod", "+a", acl, path).CombinedOutput(); err != nil {
		t.Fatalf("set test ACL: %v %s", err, output)
	}
}

func TestPrivateStateRejectsMacACLGrants(t *testing.T) {
	for _, kind := range []string{"directory", "file", "ancestor", "inherited"} {
		t.Run(kind, func(t *testing.T) {
			dir := initializePrivateStateTest(t)
			path := filepath.Join(dir, "hosts.json")
			switch kind {
			case "directory":
				addStateTestACL(t, dir, "everyone allow add_file,search")
			case "file":
				addStateTestACL(t, path, "everyone allow write")
			case "ancestor":
				addStateTestACL(t, filepath.Dir(dir), "everyone allow delete_child")
			case "inherited":
				addStateTestACL(t, dir, "everyone allow write,file_inherit,only_inherit")
				// Private temp files must be checked before writing secret bytes.
				if err := writePrivate(path, []Host{}); err == nil {
					t.Fatal("wrote state with inherited shared ACL")
				}
				return
			}
			if _, err := OpenStore(dir); err == nil {
				t.Fatal("ACL bypassed POSIX permission checks")
			}
		})
	}
}

func TestPrivateStateAllowsMacDenyOnlyAncestorACL(t *testing.T) {
	dir := initializePrivateStateTest(t)
	addStateTestACL(t, filepath.Dir(dir), "everyone deny delete")
	if _, err := OpenStore(dir); err != nil {
		t.Fatal("harmless deny-only ACL rejected", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateStateSearchOnlyAncestorRejectsMacACLGrants(t *testing.T) {
	dir := initializePrivateStateTest(t)
	parent := filepath.Dir(dir)
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0700); err != nil {
			t.Error(err)
		}
	})
	addStateTestACL(t, parent, "everyone allow delete_child")
	if err := os.Chmod(parent, 0111); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("search-only descriptor skipped ancestor ACL validation")
	}
}

func TestPrivateStateACLRejectsMalformedMetadata(t *testing.T) {
	for _, data := range [][]byte{nil, make([]byte, 12), {12, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255}} {
		if err := validateStateACL(data, true, "test"); err == nil {
			t.Fatal("malformed ACL accepted")
		}
	}
}
