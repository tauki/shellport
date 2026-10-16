package shellport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const maxPasskeys = 32

var errPasskeyNotFound = errors.New("Passkey no longer exists.")

type storedPasskey struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	RPID       string              `json:"rpId"`
	CreatedAt  time.Time           `json:"createdAt"`
	LastUsedAt *time.Time          `json:"lastUsedAt,omitempty"`
	Credential webauthn.Credential `json:"credential"`
}
type passkeyState struct {
	Version int             `json:"version"`
	UserID  []byte          `json:"userId"`
	Keys    []storedPasskey `json:"keys"`
}
type passkeySummary struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastUsedAt    *time.Time `json:"lastUsedAt,omitempty"`
	AvailableHere bool       `json:"availableHere"`
}
type passkeyUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u passkeyUser) WebAuthnName() string                       { return "Shellport owner" }
func (u passkeyUser) WebAuthnDisplayName() string                { return "Shellport" }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Store) loadPasskeys() error {
	path := filepath.Join(s.Dir, "passkeys.json")
	data, err := readPrivateState(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state passkeyState
	if err = json.Unmarshal(data, &state); err != nil {
		return errors.New("invalid passkeys.json")
	}
	if state.Version != 1 || len(state.UserID) < 16 || len(state.UserID) > 64 || len(state.Keys) > maxPasskeys {
		return errors.New("invalid passkey state")
	}
	ids := map[string]bool{}
	credentials := map[string]bool{}
	for _, key := range state.Keys {
		scope := key.RPID + ":" + string(key.Credential.ID)
		if key.ID == "" || ids[key.ID] || credentials[scope] || !validPasskeyName(key.Name) || protocol.ValidateRPID(key.RPID) != nil || len(key.Credential.ID) == 0 || len(key.Credential.ID) > 1024 || len(key.Credential.PublicKey) == 0 || key.CreatedAt.IsZero() {
			return errors.New("invalid passkey record")
		}
		ids[key.ID] = true
		credentials[scope] = true
	}
	s.passkeys = state
	return nil
}
func validPasskeyName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 80 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func copyPasskeyState(state passkeyState) passkeyState {
	data, _ := json.Marshal(state)
	var copy passkeyState
	_ = json.Unmarshal(data, &copy)
	return copy
}
func (s *Store) commitPasskeys(state passkeyState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("passkey state exceeds its supported size")
	}
	if err = writeAtomic(filepath.Join(s.Dir, "passkeys.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	s.passkeys = state
	return nil
}
func (s *Store) passkeyUser(rpID string, initialize bool) (passkeyUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.passkeys.UserID) == 0 && initialize {
		if err := s.commitPasskeys(passkeyState{Version: 1, UserID: []byte(randomID()), Keys: []storedPasskey{}}); err != nil {
			return passkeyUser{}, err
		}
	}
	state := copyPasskeyState(s.passkeys)
	user := passkeyUser{id: state.UserID, credentials: []webauthn.Credential{}}
	for _, key := range state.Keys {
		if key.RPID == rpID {
			user.credentials = append(user.credentials, key.Credential)
		}
	}
	return user, nil
}
func (s *Store) passkeySummaries(rpID string) []passkeySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := []passkeySummary{}
	for _, key := range s.passkeys.Keys {
		keys = append(keys, passkeySummary{ID: key.ID, Name: key.Name, Address: key.RPID, CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt, AvailableHere: key.RPID == rpID})
	}
	return keys
}
func (s *Store) addPasskey(rpID, name string, credential webauthn.Credential) (passkeySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.passkeys.UserID) == 0 || protocol.ValidateRPID(rpID) != nil || len(credential.ID) == 0 || len(credential.ID) > 1024 || len(credential.PublicKey) == 0 {
		return passkeySummary{}, errors.New("Invalid passkey credential.")
	}
	if len(s.passkeys.Keys) >= maxPasskeys {
		return passkeySummary{}, errors.New("Remove an old passkey before adding another.")
	}
	for _, key := range s.passkeys.Keys {
		if key.RPID == rpID && bytes.Equal(key.Credential.ID, credential.ID) {
			return passkeySummary{}, errors.New("This passkey is already registered.")
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("Passkey %d", len(s.passkeys.Keys)+1)
	}
	if !validPasskeyName(name) {
		return passkeySummary{}, errors.New("Use a passkey name of up to 80 characters.")
	}
	key := storedPasskey{ID: randomID(), Name: name, RPID: rpID, CreatedAt: time.Now().UTC(), Credential: credential}
	state := copyPasskeyState(s.passkeys)
	state.Keys = append(state.Keys, key)
	if err := s.commitPasskeys(state); err != nil {
		return passkeySummary{}, err
	}
	return passkeySummary{ID: key.ID, Name: key.Name, Address: rpID, CreatedAt: key.CreatedAt, AvailableHere: true}, nil
}
func (s *Store) usedPasskey(rpID string, credential webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := copyPasskeyState(s.passkeys)
	for i, key := range state.Keys {
		if key.RPID != rpID || !bytes.Equal(key.Credential.ID, credential.ID) {
			continue
		}
		if !bytes.Equal(key.Credential.PublicKey, credential.PublicKey) {
			return errors.New("passkey changed")
		}
		if credential.Authenticator.CloneWarning && !credential.Flags.BackupEligible {
			return errors.New("passkey counter did not advance")
		}
		if credential.Authenticator.SignCount < key.Credential.Authenticator.SignCount {
			credential.Authenticator.SignCount = key.Credential.Authenticator.SignCount
		}
		now := time.Now().UTC()
		state.Keys[i].Credential = credential
		state.Keys[i].LastUsedAt = &now
		return s.commitPasskeys(state)
	}
	return errors.New("passkey no longer exists")
}
func (s *Store) removePasskey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := copyPasskeyState(s.passkeys)
	for i, key := range state.Keys {
		if key.ID == id {
			state.Keys = append(state.Keys[:i], state.Keys[i+1:]...)
			return s.commitPasskeys(state)
		}
	}
	return errors.New("Passkey no longer exists.")
}

func (s *Store) renamePasskey(id, name string) (passkeySummary, error) {
	name = strings.TrimSpace(name)
	if !validPasskeyName(name) {
		return passkeySummary{}, errors.New("Use a passkey name of up to 80 characters.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := copyPasskeyState(s.passkeys)
	for i, key := range state.Keys {
		if key.ID != id {
			continue
		}
		state.Keys[i].Name = name
		if err := s.commitPasskeys(state); err != nil {
			return passkeySummary{}, err
		}
		return passkeySummary{ID: key.ID, Name: name, Address: key.RPID, CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt}, nil
	}
	return passkeySummary{}, errPasskeyNotFound
}
