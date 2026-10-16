package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"shellport/internal/shellport"
)

func TestProxySetupCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte(cliOldPassword), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := cliProcess(t, "init", "--data-dir", dir, "--password-file", passwordFile, "--trusted-proxy", "127.0.0.1", "--trusted-proxy", "::1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	store, err := shellport.OpenStore(dir)
	if err != nil || !reflect.DeepEqual(store.Configuration().TrustedProxies, []string{"127.0.0.1", "::1"}) {
		t.Fatal("init did not persist trusted proxy flags", err)
	}
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"--trusted-proxy", "192.0.2.0/24"}, []string{"192.0.2.0/24"}},
		{[]string{"--clear"}, nil},
	} {
		cmd = cliProcess(t, append([]string{"setup-proxy", "--data-dir", dir}, tc.args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
		store, err = shellport.OpenStore(dir)
		if err != nil || !reflect.DeepEqual(store.Configuration().TrustedProxies, tc.want) {
			t.Fatal("setup-proxy did not replace trusted proxies", err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	for _, args := range [][]string{
		{}, {"--trusted-proxy", "proxy.example.test"}, {"--trusted-proxy", "127.0.0.1/"},
		{"--trusted-proxy", "127.0.0.1", "--clear"}, {"--clear", "unexpected"},
	} {
		cmd = cliProcess(t, append([]string{"setup-proxy", "--data-dir", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatal("invalid proxy flags accepted", args, string(out))
		}
	}
	lock, err := shellport.LockInstallation(dir)
	if err != nil {
		t.Fatal(err)
	}
	cmd = cliProcess(t, "setup-proxy", "--data-dir", dir, "--trusted-proxy", "127.0.0.1")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "already running") {
		t.Fatal("setup ignored active installation", err, string(out))
	}
	lock.Close()
	after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected proxy setup changed configuration")
	}
}

func TestProxyFlagsAreValidatedBeforeInitialization(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "must-not-exist")
	cmd := cliProcess(t, "init", "--data-dir", dir, "--trusted-proxy", "proxy.example.test")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "numeric IP addresses or CIDRs") {
		t.Fatal("invalid proxy flag was not rejected before the password prompt", err, string(out))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid proxy setup touched installation data")
	}
	cmd = cliProcess(t, "serve", "--trusted-proxy", "127.0.0.1")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "use setup-proxy") {
		t.Fatal("serve silently ignored proxy setup flag", err, string(out))
	}
}
