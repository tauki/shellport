package shellport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	PasswordHash    string       `json:"passwordHash"`
	Origins         []string     `json:"origins"`
	TrustedProxies  []string     `json:"trustedProxies,omitempty"`
	KeyFile         string       `json:"keyFile"`
	AgentSocket     string       `json:"agentSocket,omitempty"`
	AllowLocalShell bool         `json:"allowLocalShell,omitempty"`
	TmuxExecutable  string       `json:"tmuxExecutable,omitempty"`
	TmuxMode        string       `json:"tmuxMode,omitempty"`
	TmuxSocket      string       `json:"tmuxSocket,omitempty"`
	TmuxDefaultMode string       `json:"tmuxDefaultMode,omitempty"`
	TmuxAdditional  *TmuxProfile `json:"tmuxAdditional,omitempty"`
	tmuxNamespace   string
	MaxSessions     int `json:"maxSessions"`
}

type Host struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Auth           string `json:"auth"`
	Tmux           bool   `json:"tmux"` // Legacy API default; browser connections choose their own type.
	HostKey        string `json:"hostKey,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	LastSession    string `json:"lastSession,omitempty"`
	LastWindow     string `json:"lastWindow,omitempty"`
	LastSessionRef string `json:"lastSessionRef,omitempty"`
}

type Store struct {
	configMu sync.Mutex
	mu       sync.RWMutex
	Dir      string
	Config   Config
	hosts    []Host
	passkeys passkeyState
}

func randomID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writePrivate(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'), 0600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if mode == 0600 {
		dir, err := openStateDirectory(filepath.Dir(path), false)
		if err != nil {
			return err
		}
		dir.Close()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".shellport-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil && mode == 0600 {
		err = validatePrivateStateFile(f)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func Initialize(dir, password string, origins []string, keyFile string, trustedProxies ...string) error {
	if err := ValidateTrustedProxies(trustedProxies); err != nil {
		return err
	}
	if len(password) < 12 || len(password) > 72 {
		return errors.New("choose an app password between 12 and 72 bytes")
	}
	if len(origins) == 0 {
		return errors.New("at least one origin is required")
	}
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return fmt.Errorf("invalid origin %q", origin)
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && isLocalHost(u.Hostname())) {
			return errors.New("use HTTPS for remote access; HTTP is allowed only on loopback")
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	dir, err = privateStateDirectory(dir)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(dir, "config.json")); err == nil {
		return errors.New("already initialized; existing data was preserved")
	} else if !os.IsNotExist(err) {
		return err
	}
	if keyFile == "" {
		keyFile = filepath.Join(dir, "id_ed25519")
		if _, err = os.Lstat(keyFile); os.IsNotExist(err) {
			pub, priv, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			block, e := ssh.MarshalPrivateKey(priv, "shellport")
			if e != nil {
				return e
			}
			if e = writeAtomic(keyFile, pem.EncodeToMemory(block), 0600); e != nil {
				return e
			}
			spub, e := ssh.NewPublicKey(pub)
			if e != nil {
				return e
			}
			if e = writeAtomic(keyFile+".pub", ssh.MarshalAuthorizedKey(spub), 0644); e != nil {
				return e
			}
		} else if err != nil {
			return err
		}
	} else {
		keyFile, err = filepath.Abs(keyFile)
		if err != nil {
			return err
		}
		if _, err = os.Stat(keyFile); err != nil {
			return err
		}
	}
	if _, err = readPrivateState(keyFile); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	cfg := Config{PasswordHash: string(hash), Origins: origins, TrustedProxies: trustedProxies, KeyFile: keyFile, MaxSessions: 4}
	if err = writePrivate(filepath.Join(dir, "hosts.json"), []Host{}); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "config.json"), cfg)
}

func isLocalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func OpenStore(dir string) (*Store, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	dir, err = privateStateDirectory(dir)
	if err != nil {
		return nil, err
	}
	data, err := readPrivateState(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("initialize Shellport first: %w", err)
	}
	var config struct {
		Config
		LegacyProxyToken string `json:"proxyToken"`
	}
	if err = json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if config.LegacyProxyToken != "" {
		return nil, errors.New("proxyToken is no longer supported; remove it and the proxy's custom token header, then configure trusted proxy addresses before restarting")
	}
	s := &Store{Dir: dir, Config: config.Config}
	if _, err = bcrypt.Cost([]byte(s.Config.PasswordHash)); err != nil {
		return nil, errors.New("invalid password hash")
	}
	if s.Config.MaxSessions < 1 || s.Config.MaxSessions > 16 {
		return nil, errors.New("maxSessions must be between 1 and 16")
	}
	if err = validateTmuxConfig(s.Config); err != nil {
		return nil, err
	}
	if len(s.Config.Origins) == 0 {
		return nil, errors.New("no allowed origins")
	}
	if _, err = parseTrustedProxies(s.Config.TrustedProxies); err != nil {
		return nil, err
	}
	data, err = readPrivateState(filepath.Join(dir, "hosts.json"))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.hosts); err != nil {
		return nil, err
	}
	if err = validateStoredHosts(s.hosts); err != nil {
		return nil, err
	}
	if err = s.loadPasskeys(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Hosts() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Host{}, s.hosts...)
}

// Password changes update the configuration while terminal requests are active.
func (s *Store) Configuration() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.Config
	cfg.Origins = append([]string(nil), cfg.Origins...)
	cfg.TrustedProxies = append([]string(nil), cfg.TrustedProxies...)
	if cfg.TmuxAdditional != nil {
		profile := *cfg.TmuxAdditional
		if profile.Service != nil {
			record := *profile.Service
			profile.Service = &record
		}
		cfg.TmuxAdditional = &profile
	}
	return cfg
}

func (s *Store) changePasswordHash(expected, next string) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Config.PasswordHash != expected {
		return errors.New("password changed")
	}
	cfg := s.Config
	cfg.PasswordHash = next
	if err := writePrivate(filepath.Join(s.Dir, "config.json"), cfg); err != nil {
		return err
	}
	s.Config.PasswordHash = next
	return nil
}
func (s *Store) Host(id string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, h := range s.hosts {
		if h.ID == id {
			return h, true
		}
	}
	return Host{}, false
}

func validateHost(h Host) error {
	if strings.TrimSpace(h.Name) == "" || len(h.Name) > 80 {
		return errors.New("enter a computer name (up to 80 characters)")
	}
	if h.Address == "" || len(h.Address) > 253 || strings.ContainsAny(h.Address, " /\\\t\r\n@") {
		return errors.New("enter a hostname or IP address, without a URL or port")
	}
	if h.Username == "" || len(h.Username) > 64 || strings.ContainsAny(h.Username, "\r\n\x00") {
		return errors.New("enter a valid SSH username")
	}
	if h.Port < 1 || h.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if h.Auth != "key" && h.Auth != "password" && h.Auth != "agent" && h.Auth != "local" {
		return errors.New("select key, password, SSH agent or this server")
	}
	if h.Auth == "local" && h.Address != "127.0.0.1" {
		return errors.New("this-server connections must use 127.0.0.1")
	}
	if strings.Contains(h.Address, ":") && net.ParseIP(h.Address) == nil {
		return errors.New("enter the SSH port in the separate port field")
	}
	return nil
}

// Persisted records must obey the same field rules as API updates. Trust is
// accepted only as a complete, internally consistent public key/fingerprint.
func validateStoredHosts(hosts []Host) error {
	if len(hosts) > 100 {
		return errors.New("computer limit reached")
	}
	ids := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if err := validateHost(h); err != nil {
			return fmt.Errorf("invalid hosts.json: %w", err)
		}
		if h.ID == "" || ids[h.ID] {
			return errors.New("invalid or duplicate computer ID in hosts.json")
		}
		ids[h.ID] = true
		if h.HostKey == "" {
			if h.Fingerprint != "" {
				return errors.New("saved server identity is incomplete")
			}
			continue
		}
		data, err := base64.StdEncoding.DecodeString(h.HostKey)
		if err != nil {
			return errors.New("saved server identity is invalid")
		}
		key, err := ssh.ParsePublicKey(data)
		if err != nil || h.Fingerprint != ssh.FingerprintSHA256(key) {
			return errors.New("saved server identity is invalid")
		}
	}
	return nil
}

func (s *Store) SaveHost(h Host) (Host, error) {
	h.Name = strings.TrimSpace(h.Name)
	h.Address = strings.TrimSpace(h.Address)
	h.Username = strings.TrimSpace(h.Username)
	if err := validateHost(h); err != nil {
		return Host{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	if h.ID == "" {
		if len(next) >= 100 {
			return Host{}, errors.New("computer limit reached")
		}
		h.ID = randomID()[:12]
		h.HostKey = ""
		h.Fingerprint = ""
		h.LastSession = ""
		h.LastWindow = ""
		h.LastSessionRef = ""
		next = append(next, h)
	} else {
		found := false
		for i, old := range next {
			if old.ID != h.ID {
				continue
			}
			found = true
			h.LastSession = ""
			h.LastWindow = ""
			h.LastSessionRef = ""
			if old.Address == h.Address && old.Port == h.Port && old.Username == h.Username && old.Auth == h.Auth {
				h.LastSession = old.LastSession
				h.LastWindow = old.LastWindow
				h.LastSessionRef = old.LastSessionRef
			}
			if old.Address == h.Address && old.Port == h.Port {
				h.HostKey = old.HostKey
				h.Fingerprint = old.Fingerprint
			} else {
				h.HostKey = ""
				h.Fingerprint = ""
			}
			next[i] = h
		}
		if !found {
			return Host{}, errors.New("computer no longer exists")
		}
	}
	if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
		return Host{}, err
	}
	s.hosts = next
	return h, nil
}

func (s *Store) DeleteHost(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		if h.ID != id {
			next = append(next, h)
		}
	}
	if len(next) == len(s.hosts) {
		return errors.New("computer no longer exists")
	}
	if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
		return err
	}
	s.hosts = next
	return nil
}

func (s *Store) RememberSession(expected Host, name string, window ...string) error {
	if !validSessionName(name) {
		return errors.New("invalid session name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	for i, host := range next {
		if host.ID != expected.ID {
			continue
		}
		if host.Address != expected.Address || host.Port != expected.Port || host.Username != expected.Username || host.Auth != expected.Auth || host.HostKey != expected.HostKey {
			return errors.New("computer changed while connecting; choose its session again")
		}
		next[i].LastSession = name
		if host.LastSession != name {
			next[i].LastWindow = ""
			next[i].LastSessionRef = ""
		}
		if len(window) > 0 {
			next[i].LastWindow = window[0]
		}
		if len(window) > 1 {
			next[i].LastSessionRef = window[1]
		}
		if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
			return errors.New("could not save the session selection; its tmux session remains on the computer")
		}
		s.hosts = next
		return nil
	}
	return errors.New("computer no longer exists")
}

func (s *Store) ForgetSession(expected Host, name string, ref ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	for i, host := range next {
		if len(ref) > 0 && host.LastSessionRef != "" && host.LastSessionRef != ref[0] {
			continue
		}
		if host.ID == expected.ID && host.Address == expected.Address && host.Port == expected.Port && host.Username == expected.Username && host.Auth == expected.Auth && host.HostKey == expected.HostKey && host.LastSession == name {
			next[i].LastSession, next[i].LastWindow = "", ""
			next[i].LastSessionRef = ""
			if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
				return errors.New("session deleted on the computer, but its Continue selection could not be cleared; refresh the list")
			}
			s.hosts = next
			return nil
		}
	}
	return nil
}

func (s *Store) RenameSession(expected Host, oldName, newName string, ref ...string) error {
	if !validSessionName(oldName) || !validNewSessionName(newName) {
		return errors.New("invalid session name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	for i, host := range next {
		if host.ID != expected.ID {
			continue
		}
		if len(ref) > 0 && host.LastSessionRef != "" && host.LastSessionRef != ref[0] {
			return nil
		}
		if host.Address != expected.Address || host.Port != expected.Port || host.Username != expected.Username || host.Auth != expected.Auth || host.HostKey != expected.HostKey {
			return errors.New("session renamed on the computer, but its saved computer changed; refresh the session list")
		}
		if host.LastSession != oldName && !(host.LastSession == "" && oldName == "shellport-"+host.ID) {
			return nil
		}
		next[i].LastSession = newName
		if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
			return errors.New("session renamed on the computer, but its Continue selection could not be updated; refresh the session list")
		}
		s.hosts = next
		return nil
	}
	return errors.New("session renamed on the computer, but its saved computer was removed")
}

func (s *Store) ForgetWindow(expected Host, window string, endedSessions map[string]bool, ref ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	for i, host := range next {
		if len(ref) > 0 && host.LastSessionRef != "" && host.LastSessionRef != ref[0] {
			continue
		}
		if host.ID != expected.ID || host.Address != expected.Address || host.Port != expected.Port || host.Username != expected.Username || host.Auth != expected.Auth || host.HostKey != expected.HostKey {
			continue
		}
		if host.LastWindow != window && !endedSessions[host.LastSession] {
			return nil
		}
		if host.LastWindow == window {
			next[i].LastWindow = ""
		}
		if endedSessions[host.LastSession] {
			next[i].LastSession, next[i].LastWindow = "", ""
			next[i].LastSessionRef = ""
		}
		if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
			return errors.New("tab closed on the computer, but its Continue selection could not be cleared; refresh the list")
		}
		s.hosts = next
		return nil
	}
	return nil
}

func (s *Store) TrustHost(id, expectedAddress string, expectedPort int, key ssh.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append([]Host{}, s.hosts...)
	for i, h := range next {
		if h.ID != id {
			continue
		}
		if h.Address != expectedAddress || h.Port != expectedPort {
			return errors.New("computer changed while verifying; check its identity again")
		}
		next[i].HostKey = base64.StdEncoding.EncodeToString(key.Marshal())
		next[i].Fingerprint = ssh.FingerprintSHA256(key)
		if err := writePrivate(filepath.Join(s.Dir, "hosts.json"), next); err != nil {
			return err
		}
		s.hosts = next
		return nil
	}
	return errors.New("computer no longer exists")
}
