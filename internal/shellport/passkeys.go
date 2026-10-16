package shellport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyFlowTTL = 3 * time.Minute

var errPasskeyAuth = errors.New("passkey authorization expired")

type passkeyFlow struct {
	kind, origin, rpID, owner string
	expires                   time.Time
	session                   webauthn.SessionData
	attempt                   *authAttempt
}
type passkeyService struct {
	mu      sync.Mutex
	loginMu sync.Mutex
	flows   map[string]passkeyFlow
}

// Each configured hostname is its own RP. Never infer a shared parent domain
// from forwarding headers or widen trust to sibling applications.
func passkeyEngine(origin string) (*webauthn.WebAuthn, string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLocalHost(u.Hostname())) {
		return nil, "", errors.New("Use an HTTPS hostname (or localhost for development) to use passkeys.")
	}
	rp := strings.ToLower(u.Hostname())
	engine, err := webauthn.New(&webauthn.Config{
		RPID: rp, RPDisplayName: "Shellport", RPOrigins: []string{origin}, AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
		Timeouts:               webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyFlowTTL}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyFlowTTL}},
	})
	return engine, rp, err
}
func passkeyCookie(kind string) string { return "shellport_passkey_" + kind }
func (s *Server) newPasskeyFlow(w http.ResponseWriter, r *http.Request, kind, rp string, session *webauthn.SessionData, attempt *authAttempt) bool {
	now := time.Now()
	s.passkeys.mu.Lock()
	defer s.passkeys.mu.Unlock()
	if s.passkeys.flows == nil {
		s.passkeys.flows = map[string]passkeyFlow{}
	}
	for id, flow := range s.passkeys.flows {
		if now.After(flow.expires) {
			delete(s.passkeys.flows, id)
		}
	}
	if old, err := r.Cookie(passkeyCookie(kind)); err == nil {
		delete(s.passkeys.flows, old.Value)
	}
	if len(s.passkeys.flows) >= 128 {
		apiError(w, 429, "Try again in a few minutes.")
		return false
	}
	if r.Context().Err() != nil {
		return false
	}
	id := randomID()
	owner := ""
	if kind == "register" {
		owner = s.auth.owner(r)
	}
	s.passkeys.flows[id] = passkeyFlow{kind: kind, rpID: rp, origin: s.auth.origin(r), owner: owner, expires: now.Add(passkeyFlowTTL), session: *session, attempt: attempt}
	http.SetCookie(w, &http.Cookie{Name: passkeyCookie(kind), Value: id, Path: "/api/passkeys", HttpOnly: true, Secure: strings.HasPrefix(s.auth.origin(r), "https://"), SameSite: http.SameSiteStrictMode, MaxAge: int(passkeyFlowTTL.Seconds())})
	return true
}
func (s *Server) takePasskeyFlow(w http.ResponseWriter, r *http.Request, kind string) (passkeyFlow, bool) {
	cookie, err := r.Cookie(passkeyCookie(kind))
	if err != nil {
		apiError(w, 400, "Passkey request expired. Try again.")
		return passkeyFlow{}, false
	}
	s.passkeys.mu.Lock()
	flow, ok := s.passkeys.flows[cookie.Value]
	delete(s.passkeys.flows, cookie.Value)
	s.passkeys.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: passkeyCookie(kind), Path: "/api/passkeys", HttpOnly: true, Secure: strings.HasPrefix(s.auth.origin(r), "https://"), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	if !ok || flow.kind != kind || time.Now().After(flow.expires) || flow.origin != s.auth.origin(r) || kind == "register" && (flow.owner == "" || flow.owner != s.auth.owner(r)) {
		apiError(w, 400, "Passkey request expired. Try again.")
		return passkeyFlow{}, false
	}
	return flow, true
}
func (s *Server) passkeyFresh(w http.ResponseWriter, r *http.Request) bool {
	if !s.auth.recent(s.auth.owner(r)) {
		respond(w, 403, map[string]string{"error": "Confirm your app password to manage passkeys.", "code": "reauth_required"})
		return false
	}
	return true
}
func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	attempt := s.auth.allowAttempt(w, r, passkeyLoginAttempt)
	if attempt == nil {
		return
	}
	defer s.auth.finishAttempt(passkeyLoginAttempt, attempt, false)
	engine, rp, err := passkeyEngine(s.auth.origin(r))
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	user, err := s.store.passkeyUser(rp, false)
	if err != nil {
		apiError(w, 500, "Could not read passkeys.")
		return
	}
	if len(user.credentials) == 0 {
		respond(w, 200, map[string]bool{"needsPassword": true})
		return
	}
	options, session, err := engine.BeginLogin(user, webauthn.WithLoginOrigin(s.auth.origin(r)))
	if err != nil {
		apiError(w, 500, "Could not prepare passkey sign-in.")
		return
	}
	if !s.newPasskeyFlow(w, r, "login", rp, session, attempt) {
		return
	}
	respond(w, 200, map[string]any{"options": options, "expiresAt": time.Now().Add(passkeyFlowTTL)})
}
func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	flow, ok := s.takePasskeyFlow(w, r, "login")
	if !ok {
		return
	}
	var input struct {
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &input) {
		return
	}
	s.passkeys.loginMu.Lock()
	defer s.passkeys.loginMu.Unlock()
	engine, _, err := passkeyEngine(flow.origin)
	if err != nil {
		apiError(w, 400, "This passkey address is unavailable.")
		return
	}
	user, err := s.store.passkeyUser(flow.rpID, false)
	if err != nil {
		apiError(w, 500, "Could not read passkeys.")
		return
	}
	response := r.Clone(r.Context())
	response.Body = io.NopCloser(bytes.NewReader(input.Credential))
	credential, err := engine.FinishLogin(user, flow.session, response)
	if err != nil {
		apiError(w, 401, "That passkey could not sign in. Use your password instead.")
		return
	}
	if err = s.store.usedPasskey(flow.rpID, *credential); err != nil {
		apiError(w, 401, "That passkey could not sign in. Use your password instead.")
		return
	}
	if s.auth.issue(w, r) {
		s.auth.finishAttempt(passkeyLoginAttempt, flow.attempt, true)
		respond(w, 200, map[string]bool{"ok": true})
	}
}
func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	_, rp, err := passkeyEngine(s.auth.origin(r))
	respond(w, 200, map[string]any{"passkeys": s.store.passkeySummaries(rp), "address": rp, "canAdd": err == nil})
}
func (s *Server) confirmPasskeyPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if s.auth.confirm(w, r, input.Password) {
		respond(w, 200, map[string]bool{"ok": true})
	}
}
func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decode(w, r, &input) || !s.passkeyFresh(w, r) {
		return
	}
	engine, rp, err := passkeyEngine(s.auth.origin(r))
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if len(s.store.passkeySummaries(rp)) >= maxPasskeys {
		apiError(w, 409, "Remove an old passkey before adding another.")
		return
	}
	user, err := s.store.passkeyUser(rp, true)
	if err != nil {
		apiError(w, 500, "Could not prepare passkey storage.")
		return
	}
	exclusions := []protocol.CredentialDescriptor{}
	for _, key := range user.credentials {
		exclusions = append(exclusions, key.Descriptor())
	}
	options, session, err := engine.BeginRegistration(user, webauthn.WithExclusions(exclusions), webauthn.WithRegistrationOrigin(s.auth.origin(r)), webauthn.WithExtensions(webauthn.WithExtensionCredProps()))
	if err != nil {
		apiError(w, 500, "Could not prepare passkey setup.")
		return
	}
	if !s.newPasskeyFlow(w, r, "register", rp, session, nil) {
		return
	}
	respond(w, 200, map[string]any{"options": options, "expiresAt": time.Now().Add(passkeyFlowTTL)})
}
func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	flow, ok := s.takePasskeyFlow(w, r, "register")
	if !ok || !s.passkeyFresh(w, r) {
		return
	}
	var input struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &input) {
		return
	}
	engine, _, err := passkeyEngine(flow.origin)
	if err != nil {
		apiError(w, 400, "This passkey address is unavailable.")
		return
	}
	user, err := s.store.passkeyUser(flow.rpID, false)
	if err != nil {
		apiError(w, 500, "Could not read passkeys.")
		return
	}
	response := r.Clone(r.Context())
	response.Body = io.NopCloser(bytes.NewReader(input.Credential))
	credential, err := engine.FinishRegistration(user, flow.session, response)
	if err != nil {
		apiError(w, 400, "Passkey setup could not be verified. Try again.")
		return
	}
	var summary passkeySummary
	err = s.auth.changePasskeys(w, flow.owner, func() error {
		var saveErr error
		summary, saveErr = s.store.addPasskey(flow.rpID, input.Name, *credential)
		return saveErr
	})
	if errors.Is(err, errPasskeyAuth) {
		return
	}
	if err != nil {
		apiError(w, 409, err.Error())
		return
	}
	respond(w, 200, summary)
}
func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyFresh(w, r) {
		return
	}
	var input struct {
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm {
		apiError(w, 400, "Confirm removing this passkey.")
		return
	}
	s.passkeys.loginMu.Lock()
	defer s.passkeys.loginMu.Unlock()
	err := s.auth.changePasskeys(w, s.auth.owner(r), func() error { return s.store.removePasskey(r.PathValue("id")) })
	if errors.Is(err, errPasskeyAuth) {
		return
	}
	if err != nil {
		apiError(w, 404, err.Error())
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &input) {
		return
	}
	var summary passkeySummary
	input.Name = strings.TrimSpace(input.Name)
	if !validPasskeyName(input.Name) {
		apiError(w, 400, "Use a passkey name of up to 80 characters.")
		return
	}
	err := s.auth.withSession(w, s.auth.owner(r), false, func() error {
		var saveErr error
		summary, saveErr = s.store.renamePasskey(r.PathValue("id"), input.Name)
		return saveErr
	})
	if errors.Is(err, errPasskeyAuth) {
		return
	}
	if errors.Is(err, errPasskeyNotFound) {
		apiError(w, 404, err.Error())
		return
	}
	if err != nil {
		apiError(w, 500, "Could not save the passkey name. Try again.")
		return
	}
	_, rp, _ := passkeyEngine(s.auth.origin(r))
	summary.AvailableHere = summary.Address == rp
	respond(w, 200, summary)
}
