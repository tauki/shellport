package shellport

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

// ResetPassword is an offline operator action, with no HTTP recovery endpoint.
// Hold the installation lock while prompting and writing so a server, setup or
// second recovery process cannot start against the configuration being changed.
func ResetPassword(dir string, prompt func() (string, error)) error {
	lock, err := LockInstallation(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	path := filepath.Join(dir, "config.json")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("password recovery requires a regular config.json, not a symbolic link")
	}
	if _, err = OpenStore(dir); err != nil {
		return err
	}
	original, err := readPrivateState(path)
	if err != nil {
		return err
	}
	var config map[string]json.RawMessage
	if err = json.Unmarshal(original, &config); err != nil {
		return err
	}
	if prompt == nil {
		return errors.New("password recovery requires a local password prompt")
	}
	password, err := prompt()
	if err != nil {
		return err
	}
	if len(password) < 12 || len(password) > 72 {
		return errors.New("choose an app password between 12 and 72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	current, err := readPrivateState(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, currentInfo) || !bytes.Equal(original, current) {
		return errors.New("configuration changed during password recovery; no password was saved, review it and retry")
	}
	// Preserve all other fields, including configuration added by a newer build.
	config["passwordHash"], err = json.Marshal(string(hash))
	if err != nil {
		return err
	}
	return writePrivate(path, config)
}
