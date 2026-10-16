package shellport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestInitializeRejectsSharedStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(dir, testPassword, []string{"http://localhost"}, ""); err == nil {
		t.Fatal("initialized in a directory writable by another account")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("initialization wrote state before rejecting unsafe directory", err)
	}
}

func TestOpenStoreRejectsReplacedHostTrust(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://localhost"}, ""); err != nil {
		t.Fatal(err)
	}
	// A well-formed attacker pin passes record validation: directory integrity
	// must reject the replacement before it can become a connection target.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(dir, "hosts.json"), []Host{{ID: "0123456789ab", Name: "Familiar computer", Address: "attacker.example", Port: 22, Username: "owner", Auth: "password", HostKey: base64.StdEncoding.EncodeToString(key.Marshal()), Fingerprint: ssh.FingerprintSHA256(key)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err != nil {
		t.Fatal("valid pin control failed", err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("loaded attacker-supplied trusted target from a shared directory")
	}
}

func TestOpenStoreRejectsWritableHostsFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://localhost"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "hosts.json"), 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("loaded group-writable host trust")
	}
}

func initializePrivateStateTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://localhost"}, ""); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPrivateStateAllowsSearchOnlyAncestors(t *testing.T) {
	for _, mode := range []os.FileMode{0111, 0100} {
		t.Run(mode.String(), func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "ancestor")
			dir := filepath.Join(parent, "data")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(parent, 0700); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal(err)
			}
			if err := Initialize(dir, testPassword, []string{"http://localhost"}, ""); err != nil {
				t.Fatal("initialize through searchable ancestor", err)
			}
			store, err := OpenStore(dir)
			if err != nil {
				t.Fatal("load through searchable ancestor", err)
			}
			if _, err = store.SaveHost(Host{Name: "Computer", Address: "example.test", Port: 22, Username: "owner", Auth: "password"}); err != nil {
				t.Fatal("save through searchable ancestor", err)
			}
			if _, err = publicKey(store.Config.KeyFile); err != nil {
				t.Fatal("read key through searchable ancestor", err)
			}
			lock, err := LockInstallation(dir)
			if err != nil {
				t.Fatal("lock through searchable ancestor", err)
			}
			if err = lock.Close(); err != nil {
				t.Fatal(err)
			}
			if err = ResetPassword(dir, func() (string, error) { return changedTestPassword, nil }); err != nil {
				t.Fatal("recover through searchable ancestor", err)
			}
			again, err := OpenStore(dir)
			if err != nil || len(again.Hosts()) != 1 {
				t.Fatal("saved state did not survive recovery", err)
			}
		})
	}
}

func TestPrivateStateRejectsWritableSearchOnlyAncestor(t *testing.T) {
	dir := initializePrivateStateTest(t)
	parent := filepath.Dir(dir)
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0700); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(parent, 0113); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("accepted an ancestor writable by another account")
	}
}

func TestPrivateStateRejectsFileSubstitutions(t *testing.T) {
	for _, name := range []string{"config.json", "hosts.json", "passkeys.json"} {
		for _, kind := range []string{"symlink", "dangling-symlink", "fifo", "directory", "shared", "oversize"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				dir := initializePrivateStateTest(t)
				path := filepath.Join(dir, name)
				original, _ := os.ReadFile(path)
				if name == "passkeys.json" {
					original = []byte(`{"version":1,"userId":"MDEyMzQ1Njc4OWFiY2RlZg==","keys":[]}`)
				}
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				switch kind {
				case "symlink", "dangling-symlink":
					target := filepath.Join(dir, "replacement")
					if kind == "symlink" {
						if err := os.WriteFile(target, original, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "shared":
					if err := os.WriteFile(path, original, 0660); err != nil {
						t.Fatal(err)
					}
				case "oversize":
					file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					err = file.Truncate(4<<20 + 1)
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := OpenStore(dir); err == nil {
					t.Fatal("unsafe state was loaded")
				}
			})
		}
	}
}

func TestPrivateStateRejectsUnsafeDirectories(t *testing.T) {
	t.Run("leaf symlink", func(t *testing.T) {
		dir := initializePrivateStateTest(t)
		link := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(link); err == nil {
			t.Fatal("symlink data directory accepted")
		}
		if err := Initialize(link, testPassword, []string{"http://localhost"}, ""); err == nil {
			t.Fatal("initialized symlink data directory")
		}
	})
	t.Run("writable parent", func(t *testing.T) {
		dir := initializePrivateStateTest(t)
		if err := os.Chmod(filepath.Dir(dir), 0777); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(dir); err == nil {
			t.Fatal("replaceable private directory accepted")
		}
	})
	t.Run("sticky parent", func(t *testing.T) {
		dir := initializePrivateStateTest(t)
		if err := os.Chmod(filepath.Dir(dir), 0777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(dir); err != nil {
			t.Fatal("protected owner directory rejected", err)
		}
	})
}

func TestPrivateStateValidatesStoredHosts(t *testing.T) {
	valid := Host{ID: "legacy-id", Name: "Computer", Address: "example.test", Port: 22, Username: "owner", Auth: "password"}
	for _, kind := range []string{"invalid address", "invalid auth", "invalid port", "empty id", "duplicate id", "too many", "bad key", "missing key", "mismatched fingerprint"} {
		t.Run(kind, func(t *testing.T) {
			dir := initializePrivateStateTest(t)
			h := valid
			hosts := []Host{h}
			switch kind {
			case "invalid address":
				hosts[0].Address = "https://example.test"
			case "invalid auth":
				hosts[0].Auth = "unknown"
			case "invalid port":
				hosts[0].Port = 0
			case "empty id":
				hosts[0].ID = ""
			case "duplicate id":
				hosts = append(hosts, h)
			case "too many":
				hosts = make([]Host, 101)
			case "bad key":
				hosts[0].HostKey = "invalid"
			case "missing key":
				hosts[0].Fingerprint = "SHA256:forged"
			case "mismatched fingerprint":
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				key, err := ssh.NewPublicKey(pub)
				if err != nil {
					t.Fatal(err)
				}
				hosts[0].HostKey = base64.StdEncoding.EncodeToString(key.Marshal())
				hosts[0].Fingerprint = "SHA256:forged"
			}
			if err := writePrivate(filepath.Join(dir, "hosts.json"), hosts); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenStore(dir); err == nil {
				t.Fatal("invalid persisted target accepted")
			}
		})
	}
}

func TestPrivateStatePreservesTrustedHostsAndExternalKey(t *testing.T) {
	keys := initializePrivateStateTest(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://localhost"}, filepath.Join(keys, "id_ed25519")); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	host, err := store.SaveHost(Host{Name: "Computer", Address: "example.test", Port: 22, Username: "owner", Auth: "password"})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.TrustHost(host.ID, host.Address, host.Port, key); err != nil {
		t.Fatal(err)
	}
	again, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, ok := again.Host(host.ID)
	if !ok || saved.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatal("restart lost saved trust")
	}
	if _, err = publicKey(again.Config.KeyFile); err != nil {
		t.Fatal("external private key rejected", err)
	}
	for _, auth := range []string{"key", "agent", "local"} {
		h := Host{Name: "Control", Address: "127.0.0.1", Port: 22, Username: "owner", Auth: auth}
		if _, err = again.SaveHost(h); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = OpenStore(dir); err != nil {
		t.Fatal("legitimate authentication modes rejected", err)
	}
	saved.Address = "other.example.test"
	if saved, err = again.SaveHost(saved); err != nil || saved.HostKey != "" || saved.Fingerprint != "" {
		t.Fatal("retargeting did not clear trust", err)
	}
	if err = os.Chmod(again.Config.KeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = publicKey(again.Config.KeyFile); err == nil {
		t.Fatal("public-key endpoint accepted an unsafe private key")
	}
}

func TestPrivateStateLockRejectsUnsafeFiles(t *testing.T) {
	dir := initializePrivateStateTest(t)
	path := filepath.Join(dir, "server.lock")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := LockInstallation(dir); err == nil {
		file.Close()
		t.Fatal("FIFO lock accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "config.json"), path); err != nil {
		t.Fatal(err)
	}
	if file, err := LockInstallation(dir); err == nil {
		file.Close()
		t.Fatal("symlink lock accepted")
	}
}

func TestPrivateStateMissingPasskeysRemainOptional(t *testing.T) {
	dir := initializePrivateStateTest(t)
	if _, err := OpenStore(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.json"), []byte(strings.Repeat(" ", 4<<20)+"[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}
