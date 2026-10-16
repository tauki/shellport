package shellport

import (
	"encoding/json"
	"path/filepath"
)

// ValidateTrustedProxies checks the same address rules used at request time.
func ValidateTrustedProxies(values []string) error {
	_, err := parseTrustedProxies(values)
	return err
}

// ConfigureTrustedProxies replaces proxy trust while Shellport is stopped.
// Keep every other configuration field and all saved installation state.
func ConfigureTrustedProxies(dir string, values []string) error {
	if err := ValidateTrustedProxies(values); err != nil {
		return err
	}
	lock, err := LockInstallation(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	store, err := OpenStore(dir)
	if err != nil {
		return err
	}
	path := filepath.Join(store.Dir, "config.json")
	data, err := readPrivateState(path)
	if err != nil {
		return err
	}
	var config map[string]json.RawMessage
	if err = json.Unmarshal(data, &config); err != nil {
		return err
	}
	if len(values) == 0 {
		delete(config, "trustedProxies")
	} else {
		config["trustedProxies"], err = json.Marshal(values)
		if err != nil {
			return err
		}
	}
	return writePrivate(path, config)
}
