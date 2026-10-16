package shellport

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"currentPassword"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Password) < 12 || len(input.Password) > 72 {
		apiError(w, 400, "Use a new password between 12 and 72 bytes.")
		return
	}
	if input.Password != input.ConfirmPassword {
		apiError(w, 400, "The new passwords do not match.")
		return
	}
	if input.Password == input.CurrentPassword {
		apiError(w, 400, "Choose a different password.")
		return
	}
	owner := s.auth.owner(r)
	expected, ok := s.auth.verifyPassword(w, r, input.CurrentPassword, passwordConfirmationAttempt)
	if !ok {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		apiError(w, 500, "Could not prepare the new password.")
		return
	}
	s.auth.mu.Lock()
	session, ok := s.auth.cookies[owner]
	if !ok || !time.Now().Before(session.expires) || expected != s.auth.hash {
		s.auth.mu.Unlock()
		respond(w, 401, map[string]string{"error": "Sign in again before changing your password.", "code": "sign_in_required"})
		return
	}
	if r.Context().Err() != nil {
		s.auth.mu.Unlock()
		return
	}
	// Persist before replacing the live hash or revoking access. Failed writes
	// preserve both the old password and every existing sign-in.
	if err = s.store.changePasswordHash(expected, string(hash)); err != nil {
		s.auth.mu.Unlock()
		apiError(w, 500, "Could not save the new password. Your current password still works.")
		return
	}
	revoked := s.auth.cookies
	s.auth.cookies = map[string]authSession{}
	s.auth.hash = string(hash)
	s.auth.mu.Unlock()
	s.mu.Lock()
	var terminals []*terminalConnection
	for id, terminal := range s.terminals {
		if _, ok = revoked[terminal.owner]; ok {
			delete(s.terminals, id)
			terminals = append(terminals, terminal)
		}
	}
	s.mu.Unlock()
	for _, terminal := range terminals {
		terminal.close()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.auth.origin(r), "https://"), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}
