package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/bcrypt"
	"shellport/internal/shellport"
)

const cliOldPassword = "synthetic-old-password"
const cliNewPassword = "synthetic-new-password"

func TestCLIProcess(t *testing.T) {
	if os.Getenv("SHELLPORT_CLI_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			version = "v0.1.0-test"
			commit = "0123456789abcdef0123456789abcdef01234567"
			if err := run(os.Args[i+1:]); err != nil {
				fmt.Fprintln(os.Stderr, "shellport:", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func cliProcess(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "SHELLPORT_CLI_TEST_HELPER=1")
	cmd.Dir = t.TempDir()
	return cmd
}

func TestVersionNeedsNoInstallation(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		cmd := cliProcess(t, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(out))
		}
		want := "Shellport v0.1.0-test (commit 0123456789ab; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
		if strings.TrimSpace(string(out)) != want {
			t.Fatalf("version: %s", out)
		}
		if _, err = os.Stat(filepath.Join(cmd.Dir, ".data")); !os.IsNotExist(err) {
			t.Fatal("version touched installation data")
		}
	}
}

func TestResetPasswordRequiresInteractiveInput(t *testing.T) {
	cmd := cliProcess(t, "reset-password", "--data-dir", filepath.Join(t.TempDir(), "must-not-initialize"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "interactive terminal") {
		t.Fatal("reset accepted piped input", err, string(out))
	}
	cmd = cliProcess(t, "reset-password", "--password", cliNewPassword)
	out, err = cmd.CombinedOutput()
	if err == nil || bytes.Contains(out, []byte(cliNewPassword)) {
		t.Fatal("reset accepted or exposed a password argument")
	}
}

func TestResetPasswordInteractiveConfirmation(t *testing.T) {
	for _, matches := range []bool{false, true} {
		name := "mismatch"
		if matches {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			if err := shellport.Initialize(dir, cliOldPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(dir, "config.json"))
			cmd := cliProcess(t, "reset-password", "--data-dir", dir)
			file, err := pty.Start(cmd)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = file.Close()
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			chunks := make(chan []byte)
			done := make(chan struct{})
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			go func() {
				defer close(done)
				defer close(chunks)
				buffer := make([]byte, 4096)
				for {
					n, err := file.Read(buffer)
					if n > 0 {
						select {
						case chunks <- append([]byte{}, buffer[:n]...):
						case <-stop:
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
			var output []byte
			until := func(marker string) {
				t.Helper()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				for !bytes.Contains(output, []byte(marker)) {
					select {
					case chunk, ok := <-chunks:
						if !ok {
							t.Fatal("prompt ended early", string(output))
						}
						output = append(output, chunk...)
					case <-timer.C:
						t.Fatal("prompt timed out", string(output))
					}
				}
			}
			until("New app password (12–72 bytes): ")
			if _, err = file.Write([]byte(cliNewPassword + "\n")); err != nil {
				t.Fatal(err)
			}
			until("Confirm new app password: ")
			confirmation := "different-test-password"
			if matches {
				confirmation = cliNewPassword
			}
			if _, err = file.Write([]byte(confirmation + "\n")); err != nil {
				t.Fatal(err)
			}
			// Drain all PTY output before waiting for the child to finish.
			for chunk := range chunks {
				output = append(output, chunk...)
			}
			<-done
			err = cmd.Wait()
			if (err == nil) != matches {
				t.Fatal("unexpected reset result", err, string(output))
			}
			if bytes.Contains(output, []byte(cliNewPassword)) || bytes.Contains(output, []byte(confirmation)) {
				t.Fatal("hidden password input was echoed")
			}
			store, openErr := shellport.OpenStore(dir)
			if openErr != nil {
				t.Fatal(openErr)
			}
			expected := cliOldPassword
			if matches {
				expected = cliNewPassword
			}
			if bcrypt.CompareHashAndPassword([]byte(store.Configuration().PasswordHash), []byte(expected)) != nil {
				t.Fatal("unexpected password after reset")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
			if !matches && !bytes.Equal(before, after) {
				t.Fatal("mismatched confirmation changed configuration")
			}
			if matches && !bytes.Contains(output, []byte("App password reset.")) {
				t.Fatal("no completion message")
			}
		})
	}
}
