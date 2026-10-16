package shellport

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivilegeFlagHelper(t *testing.T) {
	if os.Getenv("SHELLPORT_PRIVILEGE_TEST_HELPER") != "1" {
		return
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Exit(2)
	}
	fmt.Println(os.Getpid())
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestObserveActualRestrictedLinuxProcess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPrivilegeFlagHelper$")
	cmd.Env = append(os.Environ(), "SHELLPORT_PRIVILEGE_TEST_HELPER=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(line[:len(line)-1])
	if err != nil {
		t.Fatal(err)
	}
	if got := processPrivileges(pid); got.State != "blocked" {
		t.Fatal("actual kernel flag not observed", got)
	}
	// The observer itself did not set this irreversible flag or run sudo.
	if self := processPrivileges(os.Getpid()); self.State == "unknown" {
		t.Fatal("could not read observer flag")
	}
}
