package shellport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	store       *Store
	auth        *auth
	mux         *http.ServeMux
	mu          sync.Mutex
	tmuxMu      sync.Mutex
	terminals   map[string]*terminalConnection
	opening     int
	passkeys    passkeyService
	tmuxRuntime *TmuxRuntime
}

func NewServer(store *Store, assets fs.FS) *Server {
	s := &Server{store: store, auth: newAuth(store.Configuration()), mux: http.NewServeMux(), terminals: map[string]*terminalConnection{}}
	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"ok": true, "product": "shellport"})
	})
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("POST /api/logout", s.logout)
	s.mux.HandleFunc("POST /api/password", s.changePassword)
	s.mux.HandleFunc("GET /api/tmux-modes", s.tmuxModes)
	s.mux.HandleFunc("POST /api/tmux-modes", s.setTmuxDefault)
	s.mux.HandleFunc("GET /api/me", s.me)
	s.mux.HandleFunc("POST /api/passkeys/login/begin", s.beginPasskeyLogin)
	s.mux.HandleFunc("POST /api/passkeys/login/finish", s.finishPasskeyLogin)
	s.mux.HandleFunc("GET /api/passkeys", s.listPasskeys)
	s.mux.HandleFunc("POST /api/passkeys/confirm", s.confirmPasskeyPassword)
	s.mux.HandleFunc("POST /api/passkeys/register/begin", s.beginPasskeyRegistration)
	s.mux.HandleFunc("POST /api/passkeys/register/finish", s.finishPasskeyRegistration)
	s.mux.HandleFunc("DELETE /api/passkeys/{id}", s.deletePasskey)
	s.mux.HandleFunc("PATCH /api/passkeys/{id}", s.renamePasskey)
	s.mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, s.store.Hosts()) })
	s.mux.HandleFunc("POST /api/hosts", s.saveHost)
	s.mux.HandleFunc("PUT /api/hosts/{id}", s.saveHost)
	s.mux.HandleFunc("DELETE /api/hosts/{id}", s.deleteHost)
	s.mux.HandleFunc("POST /api/hosts/{id}/probe", s.probe)
	s.mux.HandleFunc("POST /api/hosts/{id}/trust", s.trust)
	s.mux.HandleFunc("POST /api/hosts/{id}/connect", s.connect)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-sessions", s.tmuxSessions)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-windows", s.tmuxWindows)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-windows/close", s.closeTmuxTab)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-windows/rename", s.renameTmuxTab)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-sessions/delete", s.deleteTmux)
	s.mux.HandleFunc("POST /api/hosts/{id}/tmux-sessions/rename", s.renameTmux)
	s.mux.HandleFunc("GET /api/terminals/{id}/terminal", s.terminal)
	s.mux.HandleFunc("DELETE /api/terminals/{id}", s.disconnect)
	s.mux.HandleFunc("POST /api/terminals/{id}/select", s.selectTerminal)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "Unknown API endpoint.") })
	if assets != nil {
		s.mux.Handle("/", http.FileServer(http.FS(assets)))
	}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/api/health" {
		s.mux.ServeHTTP(w, r)
		return
	}
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if strings.HasSuffix(r.URL.Path, "/terminal") {
		write = true
	}
	if !s.auth.allowed(r, write) {
		apiError(w, 403, "This address is not allowed. Use your configured Shellport URL.")
		return
	}
	publicPasskey := r.Method == http.MethodPost && (r.URL.Path == "/api/passkeys/login/begin" || r.URL.Path == "/api/passkeys/login/finish")
	if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/login" && r.URL.Path != "/api/me" && !publicPasskey {
		if s.auth.owner(r) == "" {
			respond(w, 401, map[string]string{"error": "Sign in to Shellport first.", "code": "sign_in_required"})
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func respond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
func apiError(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		apiError(w, 415, "Send JSON data.")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		apiError(w, 400, "Invalid request data.")
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		apiError(w, 400, "Send exactly one JSON object.")
		return false
	}
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if s.auth.login(w, r, input.Password) {
		respond(w, 200, map[string]bool{"ok": true})
	}
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	owner := s.auth.logout(w, r)
	s.mu.Lock()
	var toClose []*terminalConnection
	for id, t := range s.terminals {
		if t.owner == owner {
			delete(s.terminals, id)
			toClose = append(toClose, t)
		}
	}
	s.mu.Unlock()
	for _, t := range toClose {
		t.close()
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	owner := s.auth.owner(r)
	if owner == "" {
		_, _, err := passkeyEngine(s.auth.origin(r))
		respond(w, 200, map[string]bool{"authenticated": false, "passkeysAvailable": err == nil})
		return
	}
	cfg := s.store.Configuration()
	body := map[string]any{"authenticated": true, "agentAvailable": cfg.AgentSocket != "", "maxSessions": cfg.MaxSessions}
	_, _, passkeyError := passkeyEngine(s.auth.origin(r))
	body["passkeysAvailable"] = passkeyError == nil
	body["localShellAvailable"] = cfg.AllowLocalShell
	if data, err := publicKey(cfg.KeyFile); err == nil {
		body["publicKey"] = data
	}
	respond(w, 200, body)
}
func publicKey(path string) (string, error) {
	data, err := readPrivateState(path)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}
func (s *Server) saveHost(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Host
		Tmux *bool `json:"tmux"`
	}
	if !decode(w, r, &input) {
		return
	}
	h := input.Host
	h.ID = r.PathValue("id")
	// Retain legacy API defaults without exposing a capability switch in the UI.
	if input.Tmux != nil {
		h.Tmux = *input.Tmux
	} else if previous, ok := s.store.Host(h.ID); ok {
		h.Tmux = previous.Tmux
	} else {
		h.Tmux = true
	}
	if h.Auth == "local" && !s.store.Configuration().AllowLocalShell {
		apiError(w, 403, "This-server terminals have not been enabled by the operator.")
		return
	}
	h, err := s.store.SaveHost(h)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	respond(w, 200, h)
}
func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteHost(r.PathValue("id")); err != nil {
		apiError(w, 404, err.Error())
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (s *Server) getHost(w http.ResponseWriter, r *http.Request) (Host, bool) {
	h, ok := s.store.Host(r.PathValue("id"))
	if !ok {
		apiError(w, 404, "Computer no longer exists.")
	}
	return h, ok
}
func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	p, _, err := probeHost(r.Context(), h)
	if err != nil {
		apiError(w, 502, err.Error())
		return
	}
	respond(w, 200, p)
}
func (s *Server) trust(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &input) {
		return
	}
	p, key, err := probeHost(r.Context(), h)
	if err != nil {
		apiError(w, 502, err.Error())
		return
	}
	if input.Fingerprint != p.Fingerprint {
		apiError(w, 409, "The server identity changed during verification. Check again.")
		return
	}
	if err = s.store.TrustHost(h.ID, h.Address, h.Port, key); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
		Cols       int    `json:"cols"`
		Mode       string `json:"mode"`
		Rows       int    `json:"rows"`
		Session    string `json:"session"`
		Create     bool   `json:"create"`
		SessionRef string `json:"sessionRef"`
		Window     string `json:"window"`
		NewWindow  bool   `json:"newWindow"`
		Remember   *bool  `json:"remember"`
		Direct     *bool  `json:"direct"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !validSize(input.Cols, input.Rows) {
		apiError(w, 400, "Invalid terminal size.")
		return
	}
	// The connection can bypass tmux without changing the saved computer or its
	// last selected session. The terminal retains its effective shell type.
	terminalHost := h
	if input.Direct != nil {
		terminalHost.Tmux = !*input.Direct
	}
	useTmux := terminalHost.Tmux
	if input.Mode != "" && (h.Auth != "local" || !useTmux || !input.Create || input.Mode != TmuxIndependent && input.Mode != TmuxManaged) {
		apiError(w, 400, "Choose a mode only when creating a local session.")
		return
	}
	if useTmux && !input.Create && input.Session == "" && input.SessionRef == "" && h.LastSessionRef != "" {
		input.Session, input.SessionRef = h.LastSession, h.LastSessionRef
	}
	if (!useTmux && (input.Session != "" || input.Create || input.Window != "" || input.NewWindow || input.SessionRef != "")) || input.Create && input.Session != "" && !validNewSessionName(input.Session) || input.Session != "" && !validSessionName(input.Session) || input.Window != "" && !tmuxWindowID.MatchString(input.Window) || input.NewWindow && input.Window != "" || input.Create && (input.Window != "" || input.NewWindow || input.SessionRef != "") {
		apiError(w, 400, "Choose a tmux session, or use a new name of up to 64 letters, numbers, spaces, hyphens or underscores.")
		return
	}
	owner := s.auth.owner(r)
	s.mu.Lock()
	if len(s.terminals)+s.opening >= s.store.Configuration().MaxSessions {
		s.mu.Unlock()
		apiError(w, 409, "Close a terminal before opening another.")
		return
	}
	s.opening++
	s.mu.Unlock()
	if useTmux {
		s.tmuxMu.Lock()
		defer s.tmuxMu.Unlock()
	}
	t, err := openTerminal(r.Context(), s.store.Configuration(), terminalHost, input.Password, input.Passphrase, input.Cols, input.Rows, tmuxChoice{Mode: input.Mode, Name: input.Session, Create: input.Create, Ref: input.SessionRef, Window: input.Window, NewWindow: input.NewWindow})
	s.mu.Lock()
	s.opening--
	if err != nil {
		s.mu.Unlock()
		code := 502
		var selectionError *tmuxError
		if errors.As(err, &selectionError) {
			code = selectionError.status
		}
		apiError(w, code, err.Error())
		return
	}
	if s.auth.owner(r) != owner || r.Context().Err() != nil {
		s.mu.Unlock()
		t.close()
		if r.Context().Err() == nil {
			apiError(w, 401, "Your sign-in expired. Sign in again.")
		}
		return
	}
	if useTmux && (input.Remember == nil || *input.Remember) {
		if err = s.store.RememberSession(h, t.tmuxSession, t.tmuxWindow.ID, t.tmuxRef); err != nil {
			s.mu.Unlock()
			t.close()
			apiError(w, 409, err.Error())
			return
		}
		h.LastSession = t.tmuxSession
		h.LastWindow = t.tmuxWindow.ID
		h.LastSessionRef = t.tmuxRef
	}
	t.owner = owner
	t.renames = make(chan string, 1)
	t.windowRenames = make(chan TmuxWindow, 1)
	s.terminals[t.id] = t
	s.mu.Unlock()
	time.AfterFunc(30*time.Second, func() {
		s.mu.Lock()
		current, ok := s.terminals[t.id]
		if ok && !current.attached {
			delete(s.terminals, t.id)
		} else {
			ok = false
		}
		s.mu.Unlock()
		if ok {
			t.close()
		}
	})
	respond(w, 200, map[string]any{"id": t.id, "host": h, "tmux": useTmux, "session": t.tmuxSession, "sessionRef": t.tmuxRef, "window": t.tmuxWindow})
}

func (s *Server) tmuxSessions(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &input) {
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	sessions, err := hostTmuxSessions(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase)
	if s.auth.owner(r) != owner {
		apiError(w, 401, "Your sign-in expired. Sign in again.")
		return
	}
	if err != nil {
		if errors.Is(err, errTmuxUnavailable) {
			respond(w, 200, map[string]any{"available": false, "sessions": []TmuxSession{}, "reason": err.Error()})
			return
		}
		apiError(w, 502, err.Error())
		return
	}
	response := map[string]any{"available": true, "sessions": sessions, "lastSession": h.LastSession, "lastSessionRef": h.LastSessionRef, "defaultSession": "shellport-" + h.ID}
	if h.Auth == "local" {
		cfg := s.store.Configuration()
		response["defaultMode"] = defaultTmuxMode(cfg)
		modes := []string{}
		for _, p := range tmuxProfiles(cfg) {
			modes = append(modes, primaryTmuxMode(p))
		}
		response["modes"] = modes
	}
	respond(w, 200, response)
}

func (s *Server) tmuxWindows(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Session    string `json:"session"`
		Ref        string `json:"ref"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !validSessionName(input.Session) || len(input.Ref) != 64 {
		apiError(w, 400, "Choose a session from the current list.")
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	var windows []TmuxWindow
	var selectedName string
	err := withHostTmuxRef(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase, input.Session, input.Ref, func(run tmuxRunner) error {
		selected, err := chooseTmux(r.Context(), run, h, tmuxChoice{Name: input.Session, Ref: input.Ref}, 0, 0)
		if err != nil {
			return err
		}
		selectedName = selected.Name
		windows, err = listTmuxWindows(r.Context(), run, selected)
		return err
	})
	if err != nil {
		tmuxAPIError(w, err)
		return
	}
	if s.auth.owner(r) != owner {
		apiError(w, 401, "Your sign-in expired. Sign in again.")
		return
	}
	last := ""
	latest, _ := s.store.Host(h.ID)
	if latest.LastSession == selectedName && (latest.LastSessionRef == "" || latest.LastSessionRef == input.Ref) {
		last = latest.LastWindow
	}
	respond(w, 200, map[string]any{"windows": windows, "lastWindow": last})
}

func tmuxAPIError(w http.ResponseWriter, err error) {
	code := 502
	var selected *tmuxError
	if errors.As(err, &selected) {
		code = selected.status
	}
	apiError(w, code, err.Error())
}

func (s *Server) deleteTmux(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Session    string `json:"session"`
		Ref        string `json:"ref"`
		Confirm    bool   `json:"confirm"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm || !validSessionName(input.Session) || len(input.Ref) != 64 {
		apiError(w, 400, "Confirm deletion of a session from the current list.")
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	err := withHostTmuxRef(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase, input.Session, input.Ref, func(run tmuxRunner) error {
		return deleteTmuxSession(r.Context(), run, input.Session, input.Ref, func() error {
			current, exists := s.store.Host(h.ID)
			if s.auth.owner(r) != owner {
				return &tmuxError{401, "Your sign-in expired. Sign in again."}
			}
			if !exists || current.Address != h.Address || current.Port != h.Port || current.Username != h.Username || current.Auth != h.Auth || current.HostKey != h.HostKey {
				return &tmuxError{409, "Computer changed. Refresh before deleting a session."}
			}
			return nil
		})
	})
	if err != nil {
		tmuxAPIError(w, err)
		return
	}
	s.mu.Lock()
	var ended []*terminalConnection
	for id, terminal := range s.terminals {
		if terminal.host.ID == h.ID && terminal.tmuxSession == input.Session && terminal.tmuxRef == input.Ref {
			delete(s.terminals, id)
			ended = append(ended, terminal)
		}
	}
	s.mu.Unlock()
	for _, terminal := range ended {
		terminal.close()
	}
	if err = s.store.ForgetSession(h, input.Session, input.Ref); err != nil {
		tmuxAPIError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"deleted": true})
}

func (s *Server) renameTmux(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input struct {
		Session    string `json:"session"`
		Ref        string `json:"ref"`
		Name       string `json:"name"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !validSessionName(input.Session) || len(input.Ref) != 64 || !validNewSessionName(input.Name) {
		apiError(w, 400, "Choose a session from the current list and use up to 64 letters, numbers, spaces, hyphens or underscores.")
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	var renamed TmuxSession
	err := withHostTmuxRef(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase, input.Session, input.Ref, func(run tmuxRunner) error {
		var err error
		renamed, err = renameTmuxSession(r.Context(), run, input.Session, input.Ref, input.Name, func() error {
			current, exists := s.store.Host(h.ID)
			if s.auth.owner(r) != owner {
				return &tmuxError{401, "Your sign-in expired. Sign in again."}
			}
			if !exists || current.Address != h.Address || current.Port != h.Port || current.Username != h.Username || current.Auth != h.Auth || current.HostKey != h.HostKey {
				return &tmuxError{409, "Computer changed. Refresh before renaming a session."}
			}
			return nil
		})
		return err
	})
	if err != nil {
		tmuxAPIError(w, err)
		return
	}
	s.mu.Lock()
	for _, terminal := range s.terminals {
		if terminal.host.ID == h.ID && terminal.tmuxRef == input.Ref {
			terminal.tmuxSession = renamed.Name
			// Coalesce repeated renames without blocking an open terminal.
			select {
			case terminal.renames <- renamed.Name:
			default:
				select {
				case <-terminal.renames:
				default:
				}
				select {
				case terminal.renames <- renamed.Name:
				default:
				}
			}
		}
	}
	s.mu.Unlock()
	if err = s.store.RenameSession(h, input.Session, renamed.Name, input.Ref); err != nil {
		tmuxAPIError(w, err)
		return
	}
	updated, _ := s.store.Host(h.ID)
	respond(w, 200, map[string]any{"session": renamed, "host": updated})
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	owner := s.auth.owner(r)
	s.mu.Lock()
	t, ok := s.terminals[r.PathValue("id")]
	if ok && t.owner == owner {
		delete(s.terminals, t.id)
	} else {
		ok = false
	}
	s.mu.Unlock()
	// Closing an expired, already-closed or another device's terminal is a no-op.
	// Do not reveal whether another signed-in device owns this connection.
	if ok {
		t.close()
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func (s *Server) selectTerminal(w http.ResponseWriter, r *http.Request) {
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	s.mu.Lock()
	t, ok := s.terminals[r.PathValue("id")]
	if !ok || t.owner != owner || !t.attached || t.ctx.Err() != nil || t.tmuxSession == "" {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		apiError(w, 404, "This terminal is no longer connected.")
		return
	}
	if s.auth.owner(r) != owner {
		apiError(w, 401, "Your sign-in expired. Sign in again.")
		return
	}
	if err := s.store.RememberSession(t.host, t.tmuxSession, t.tmuxWindow.ID, t.tmuxRef); err != nil {
		apiError(w, 409, err.Error())
		return
	}
	host, _ := s.store.Host(t.host.ID)
	respond(w, 200, host)
}

func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	owner := s.auth.owner(r)
	s.mu.Lock()
	t, ok := s.terminals[r.PathValue("id")]
	if !ok || t.owner != owner || t.attached {
		s.mu.Unlock()
		apiError(w, 404, "Terminal unavailable. Reconnect to open a new connection.")
		return
	}
	t.attached = true
	s.mu.Unlock()
	// The outer middleware already checks the full exact origin, including scheme.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		s.removeTerminal(t)
		return
	}
	defer c.CloseNow()
	ctx, cancel := context.WithDeadline(r.Context(), s.auth.expiry(owner))
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	defer cancel()
	defer s.removeTerminal(t)
	c.SetReadLimit(64 << 10)
	var writes sync.Mutex
	send := func(kind websocket.MessageType, b []byte) error {
		writes.Lock()
		defer writes.Unlock()
		bounded, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		return c.Write(bounded, kind, b)
	}
	done := make(chan error, 3)
	go func() {
		b := make([]byte, 16<<10)
		for {
			n, err := t.out.Read(b)
			if n > 0 {
				if e := send(websocket.MessageBinary, b[:n]); e != nil {
					done <- e
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		err := t.wait()
		if err != nil {
			_ = send(websocket.MessageText, []byte(`{"type":"exit","message":"Remote shell ended. If tmux is enabled, check that it is installed."}`))
		}
		if t.writer != nil {
			_ = t.writer.Close()
		}
	}()
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case name := <-t.renames:
				data, _ := json.Marshal(map[string]string{"type": "session-renamed", "session": name})
				if err := send(websocket.MessageText, data); err != nil {
					cancel()
					return
				}
			case window := <-t.windowRenames:
				data, _ := json.Marshal(map[string]string{"type": "tab-renamed", "window": window.ID, "name": window.Name})
				if err := send(websocket.MessageText, data); err != nil {
					cancel()
					return
				}
			case <-ticker.C:
				pingCtx, stop := context.WithTimeout(ctx, 8*time.Second)
				err := c.Ping(pingCtx)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		for {
			kind, data, err := c.Read(ctx)
			if err != nil {
				done <- err
				return
			}
			if kind == websocket.MessageBinary {
				if _, err = t.in.Write(data); err != nil {
					done <- err
					return
				}
				continue
			}
			var resize struct {
				Type  string `json:"type"`
				Cols  int    `json:"cols"`
				Rows  int    `json:"rows"`
				Nonce string `json:"nonce"`
			}
			if json.Unmarshal(data, &resize) != nil {
				done <- errors.New("invalid terminal message")
				return
			}
			if resize.Type == "ping" && validHeartbeatNonce(resize.Nonce) {
				pong, _ := json.Marshal(map[string]string{"type": "pong", "nonce": resize.Nonce})
				if err = send(websocket.MessageText, pong); err != nil {
					done <- err
					return
				}
				continue
			}
			if resize.Type != "resize" || !validSize(resize.Cols, resize.Rows) {
				done <- errors.New("invalid terminal message")
				return
			}
			if err = t.resize(resize.Cols, resize.Rows); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = c.Close(websocket.StatusNormalClosure, "Connection closed; reconnect to resume")
}

func validHeartbeatNonce(nonce string) bool {
	if len(nonce) == 0 || len(nonce) > 64 {
		return false
	}
	for _, c := range nonce {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) removeTerminal(t *terminalConnection) {
	s.mu.Lock()
	delete(s.terminals, t.id)
	s.mu.Unlock()
	t.close()
}
func (s *Server) Close() {
	s.mu.Lock()
	terminals := s.terminals
	s.terminals = map[string]*terminalConnection{}
	s.mu.Unlock()
	for _, t := range terminals {
		t.close()
	}
}
