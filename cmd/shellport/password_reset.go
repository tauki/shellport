package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"
	"shellport/internal/shellport"
)

func runPasswordReset(args []string) error {
	flags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	dir := flags.String("data-dir", ".data", "existing private installation data directory")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: shellport reset-password --data-dir PATH\n\nStop Shellport and its automatic restarter first, then run as its OS account.\nPrompts locally for a new password twice; no current password is required.\nSaved computers, SSH keys and passkeys are preserved. Restart to sign in again.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("reset-password accepts only --data-dir; passwords must be entered at the local prompt")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("reset-password needs an interactive terminal; run it locally or through an interactive SSH terminal as the server's OS account")
	}
	err := shellport.ResetPassword(*dir, promptResetPassword)
	if err != nil {
		return err
	}
	fmt.Println("App password reset. Start Shellport and sign in with the new password or an existing passkey.")
	fmt.Println("Computers, SSH keys and passkeys were preserved. Update any separate operator password file yourself.")
	return nil
}

func promptResetPassword() (string, error) {
	fmt.Fprint(os.Stderr, "New app password (12–72 bytes): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	defer clear(password)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm new app password: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	defer clear(confirm)
	if err != nil {
		return "", err
	}
	if string(password) != string(confirm) {
		return "", errors.New("passwords did not match; the current password was preserved")
	}
	return string(password), nil
}
