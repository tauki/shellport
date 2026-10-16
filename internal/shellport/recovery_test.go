package shellport

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestResetPasswordPreservesInstallationAndPasskeys(t *testing.T) {
	f := newPasskeyFixture(t)
	authenticator := newTestAuthenticator(t)
	f.register(t, authenticator)
	if _, err := f.store.SaveHost(Host{Name: "Saved computer", Address: "server.example.test", Port: 22, Username: "demo", Auth: "key", Tmux: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.store.Dir, "config.json")
	var before map[string]json.RawMessage
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &before); err != nil {
		t.Fatal(err)
	}
	before["futureSetting"] = json.RawMessage([]byte("{\"number\":9007199254740993,\"enabled\":true}"))
	if err := writePrivate(path, before); err != nil {
		t.Fatal(err)
	}
	kept := map[string][]byte{}
	for _, name := range []string{"hosts.json", "id_ed25519", "id_ed25519.pub", "passkeys.json"} {
		var err error
		kept[name], err = os.ReadFile(filepath.Join(f.store.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.app.Close()
	if err := ResetPassword(f.store.Dir, func() (string, error) {
		// The lock also excludes a new server or second reset during prompting.
		if lock, err := LockInstallation(f.store.Dir); err == nil {
			lock.Close()
			t.Fatal("recovery did not hold installation lock")
		}
		return changedTestPassword, nil
	}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	var after map[string]json.RawMessage
	if err := json.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	delete(before, "passwordHash")
	delete(after, "passwordHash")
	oldJSON, _ := json.Marshal(before)
	newJSON, _ := json.Marshal(after)
	if !bytes.Equal(oldJSON, newJSON) {
		t.Fatal("recovery changed non-password configuration")
	}
	for name, want := range kept {
		got, err := os.ReadFile(filepath.Join(f.store.Dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("recovery changed", name, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || bytes.Contains(data, []byte(changedTestPassword)) {
		t.Fatal("unsafe password persistence", err)
	}
	store, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	f.app = NewServer(store, nil)
	t.Cleanup(f.app.Close)
	// Restart invalidates prior sign-ins, and the old password no longer works.
	f.call(t, "GET", "/api/passkeys", nil, nil, 401)
	f.call(t, "POST", "/api/login", map[string]string{"password": testPassword}, nil, 401)
	f.call(t, "POST", "/api/login", map[string]string{"password": changedTestPassword}, nil, 200)
	f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
	options := f.begin(t, "login")
	f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": authenticator.assertion(t, options, f.origin, passkeyTestRP, 5, 1)}, nil, 200)
}

func TestResetPasswordRefusesLockAndInvalidInput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	before, _ := os.ReadFile(path)
	lock, err := LockInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	prompted := false
	if err = ResetPassword(dir, func() (string, error) { prompted = true; return changedTestPassword, nil }); err == nil || prompted {
		t.Fatal("reset ignored the running installation lock", err)
	}
	lock.Close()
	for _, password := range []string{"", "short", strings.Repeat("界", 25)} {
		if err = ResetPassword(dir, func() (string, error) { return password, nil }); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	cancelled := errors.New("prompt cancelled")
	if err = ResetPassword(dir, func() (string, error) { return "", cancelled }); !errors.Is(err, cancelled) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed recovery changed the password")
	}
	lock, err = LockInstallation(dir)
	if err != nil {
		t.Fatal("failed recovery retained its lock", err)
	}
	lock.Close()
}

func TestResetPasswordRefusesConfigurationReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	before, _ := os.ReadFile(path)
	err := ResetPassword(dir, func() (string, error) {
		// Even replacement with identical bytes is an external configuration edit.
		return changedTestPassword, writeAtomic(path, before, 0600)
	})
	if err == nil || !strings.Contains(err.Error(), "configuration changed") {
		t.Fatal("replaced configuration was overwritten", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("recovery overwrote the external edit")
	}
	var cfg Config
	_ = json.Unmarshal(after, &cfg)
	if bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(testPassword)) != nil {
		t.Fatal("old password was not preserved")
	}
	if err = os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	prompted := false
	if err = ResetPassword(dir, func() (string, error) { prompted = true; return changedTestPassword, nil }); err == nil || prompted {
		t.Fatal("symbolic config was changed", err)
	}
}

func TestResetPasswordRejectsServerLoadedBeforeRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	stale, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = ResetPassword(dir, func() (string, error) { return changedTestPassword, nil }); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewTmuxRuntime(stale)
	if err == nil {
		runtime.Close()
		t.Fatal("server started with its pre-recovery password")
	}
	current, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err = NewTmuxRuntime(current)
	if err != nil {
		t.Fatal("fresh server could not start after recovery", err)
	}
	runtime.Close()
}
