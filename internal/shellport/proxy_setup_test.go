package shellport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigureTrustedProxiesPreservesInstallation(t *testing.T) {
	f := newPasskeyFixture(t)
	f.register(t, newTestAuthenticator(t))
	if _, err := f.store.SaveHost(Host{Name: "Saved computer", Address: "server.example.test", Port: 22, Username: "demo", Auth: "key", Tmux: true}); err != nil {
		t.Fatal(err)
	}
	f.app.Close()
	path := filepath.Join(f.store.Dir, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var before map[string]json.RawMessage
	if err = json.Unmarshal(data, &before); err != nil {
		t.Fatal(err)
	}
	before["futureSetting"] = json.RawMessage(`{"number":9007199254740993,"enabled":true}`)
	if err = writePrivate(path, before); err != nil {
		t.Fatal(err)
	}
	kept := map[string][]byte{}
	for _, name := range []string{"hosts.json", "passkeys.json", "id_ed25519", "id_ed25519.pub"} {
		kept[name], err = os.ReadFile(filepath.Join(f.store.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	values := []string{"127.0.0.1", "::1", "192.0.2.0/24"}
	if err = ConfigureTrustedProxies(f.store.Dir, values); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(f.store.Dir)
	if err != nil || !reflect.DeepEqual(store.Configuration().TrustedProxies, values) {
		t.Fatal("proxy trust was not saved", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]json.RawMessage
	if err = json.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	delete(after, "trustedProxies")
	want, _ := json.Marshal(before)
	got, _ := json.Marshal(after)
	if !bytes.Equal(got, want) {
		t.Fatal("proxy setup changed other configuration")
	}
	for name, want := range kept {
		got, err := os.ReadFile(filepath.Join(f.store.Dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("proxy setup changed", name, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("configuration is no longer private", err)
	}
	if err = ConfigureTrustedProxies(f.store.Dir, nil); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(f.store.Dir)
	if err != nil || len(store.Configuration().TrustedProxies) != 0 {
		t.Fatal("proxy trust was not cleared", err)
	}
}

func TestConfigureTrustedProxiesRefusesActiveOrInvalidSetup(t *testing.T) {
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
	if err = ConfigureTrustedProxies(dir, []string{"127.0.0.1"}); err == nil {
		t.Fatal("proxy setup ignored the running installation lock")
	}
	lock.Close()
	if err = ConfigureTrustedProxies(dir, []string{"127.0.0.1", "proxy.example.test"}); err == nil {
		t.Fatal("invalid proxy setup accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed proxy setup changed configuration")
	}
	if err = ConfigureTrustedProxies(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal("failed proxy setup retained its lock", err)
	}
}

func TestRemovedProxyTokenIsNotSilentlyIgnored(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	data, _ := os.ReadFile(path)
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	config["proxyToken"], _ = json.Marshal(token)
	if err := writePrivate(path, config); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "no longer supported") || strings.Contains(err.Error(), token) {
		t.Fatal("removed token configuration silently lost protection or exposed its value", err)
	}
}

func TestInitializeRejectsInvalidProxyBeforeWriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "must-not-exist")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, "", "proxy.example.test"); err == nil {
		t.Fatal("invalid proxy setup accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid proxy setup wrote installation data")
	}
}
