package shellport

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthenticationIsolationThroughTrustedProxy(t *testing.T) {
	f := newTrustedProxyFixture(t)
	call := func(client, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8088"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Origin", passkeyTestOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Host", passkeyTestRP)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-For", client)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		f.app.ServeHTTP(w, r)
		return w
	}
	password := `{"password":"` + testPassword + `"}`
	initial := call("192.0.2.2", "/api/login", password, nil)
	if initial.Code != 200 {
		t.Fatal(initial.Code, initial.Body.String())
	}
	owner := initial.Result().Cookies()[0]
	for range 10 {
		if w := call("192.0.2.1", "/api/login", `{"password":"wrong"}`, nil); w.Code != 401 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := call("192.0.2.1", "/api/login", password, nil); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("attacker budget not enforced", w.Code)
	}
	for _, tc := range []struct {
		client, path, body string
		cookie             *http.Cookie
	}{
		{"192.0.2.2", "/api/login", password, nil},
		{"192.0.2.1", "/api/passkeys/login/begin", `{}`, nil},
		{"192.0.2.1", "/api/passkeys/confirm", password, owner},
		{"192.0.2.2", "/api/passkeys/confirm", password, owner},
	} {
		if w := call(tc.client, tc.path, tc.body, tc.cookie); w.Code != 200 {
			t.Fatalf("%s from %s: %d %s", tc.path, tc.client, w.Code, w.Body.String())
		}
	}
	for range 9 {
		call("192.0.2.1", "/api/passkeys/login/begin", `{}`, nil)
	}
	if w := call("192.0.2.1", "/api/passkeys/login/begin", `{}`, nil); w.Code != 429 {
		t.Fatal("passkey challenge budget not enforced", w.Code)
	}
	if w := call("192.0.2.2", "/api/passkeys/login/begin", `{}`, nil); w.Code != 200 {
		t.Fatal("passkey client isolation", w.Code)
	}
	change := `{"currentPassword":"` + testPassword + `","password":"` + changedTestPassword + `","confirmPassword":"` + changedTestPassword + `"}`
	if w := call("192.0.2.1", "/api/password", change, owner); w.Code != 200 {
		t.Fatal("public traffic blocked password rotation", w.Code, w.Body.String())
	}
}

func TestAuthenticationProxyIdentityRejectsSpoofingAndCanonicalizes(t *testing.T) {
	for _, tc := range []struct {
		name, peer, address string
		duplicate           bool
		want                string
	}{
		{"ipv4", "127.0.0.1:10", "192.0.2.1", false, "192.0.2.1"},
		{"mapped-ipv4", "[::ffff:127.0.0.1]:10", "::ffff:192.0.2.1", false, "192.0.2.1"},
		{"ipv6", "[::1]:10", "2001:0db8::1", false, "2001:db8::1"},
		{"untrusted-peer", "192.0.2.9:10", "192.0.2.1", false, ""},
		{"missing-ip", "127.0.0.1:10", "", false, ""},
		{"list", "127.0.0.1:10", "192.0.2.1, 192.0.2.2", false, ""},
		{"duplicate", "127.0.0.1:10", "192.0.2.1", true, ""},
		{"port", "127.0.0.1:10", "192.0.2.1:80", false, ""},
		{"zone", "127.0.0.1:10", "fe80::1%lo0", false, ""},
		{"unspecified", "127.0.0.1:10", "0.0.0.0", false, ""},
		{"mapped-unspecified", "127.0.0.1:10", "::ffff:0.0.0.0", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuth(Config{TrustedProxies: []string{"127.0.0.1", "::1"}})
			r := httptest.NewRequest("POST", "http://localhost/api/login", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.address)
			if tc.duplicate {
				r.Header.Add("X-Forwarded-For", tc.address)
			}
			got, ok := a.client(r)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatal(got, ok)
			}
		})
	}
	f := newPasskeyFixture(t)
	for _, peer := range []string{"127.0.0.1:1234", "192.0.2.9:1234"} {
		for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
			r := httptest.NewRequest("POST", passkeyTestOrigin+"/api/login", strings.NewReader(`{"password":"`+testPassword+`"}`))
			r.RemoteAddr = peer
			r.Header.Set("Origin", passkeyTestOrigin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(header, "192.0.2.1")
			w := httptest.NewRecorder()
			f.app.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("peer=%s spoofed %s admitted: %d", peer, header, w.Code)
			}
		}
	}
}

func TestAuthenticationBudgetsBoundConcurrentAndDistributedAttempts(t *testing.T) {
	a := newAuth(Config{})
	r := httptest.NewRequest("POST", "http://localhost/api/login", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	var group sync.WaitGroup
	accepted := make(chan *authAttempt, 50)
	for range 50 {
		group.Go(func() {
			if attempt := a.allowAttempt(httptest.NewRecorder(), r, passwordLoginAttempt); attempt != nil {
				accepted <- attempt
			}
		})
	}
	group.Wait()
	close(accepted)
	if len(accepted) != 10 {
		t.Fatal("concurrent reservations", len(accepted))
	}
	for attempt := range accepted {
		a.finishAttempt(passwordLoginAttempt, attempt, false)
	}
	for client := 2; client <= 10; client++ {
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", client)
		for range 10 {
			attempt := a.allowAttempt(httptest.NewRecorder(), r, passwordLoginAttempt)
			if attempt == nil {
				t.Fatal("global ceiling too low")
			}
			a.finishAttempt(passwordLoginAttempt, attempt, false)
		}
	}
	r.RemoteAddr = "192.0.2.11:1234"
	w := httptest.NewRecorder()
	if a.allowAttempt(w, r, passwordLoginAttempt) != nil || w.Code != 429 {
		t.Fatal("global ceiling missing")
	}
	if a.allowAttempt(httptest.NewRecorder(), r, passkeyLoginAttempt) == nil {
		t.Fatal("password ceiling blocked passkeys")
	}
	a.cookies["owner"] = authSession{expires: time.Now().Add(time.Hour)}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "owner"})
	if a.allowAttempt(httptest.NewRecorder(), r, passwordConfirmationAttempt) == nil {
		t.Fatal("public ceiling blocked owner")
	}
	for _, purpose := range []attemptPurpose{passwordLoginAttempt, passkeyLoginAttempt, passwordConfirmationAttempt} {
		for _, attempt := range a.attempts[purpose] {
			attempt.at = time.Now().Add(-2 * time.Minute)
		}
	}
	// Completed failures expire; pending work keeps its reservation until finished.
	if a.allowAttempt(httptest.NewRecorder(), r, passwordLoginAttempt) == nil || len(a.attempts[passwordLoginAttempt]) != 1 {
		t.Fatal("expired budget did not drain")
	}
	for _, attempt := range a.attempts[passkeyLoginAttempt] {
		attempt.at = time.Now().Add(-2 * time.Minute)
	}
	if a.allowAttempt(httptest.NewRecorder(), r, passkeyLoginAttempt) == nil || len(a.attempts[passkeyLoginAttempt]) != 2 {
		t.Fatal("pending reservation expired")
	}
	for _, owner := range []string{"unknown", "expired"} {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: cookieName, Value: owner})
		a.cookies["expired"] = authSession{expires: time.Now().Add(-time.Second)}
		if a.allowAttempt(httptest.NewRecorder(), r, passwordConfirmationAttempt) != nil {
			t.Fatal("invalid session received reserved capacity")
		}
	}
}

func TestSuccessfulPasskeyAuthenticationRefundsChallengeBudget(t *testing.T) {
	f := newPasskeyFixture(t)
	a := newTestAuthenticator(t)
	f.register(t, a)
	for counter := uint32(1); counter <= 11; counter++ {
		f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
		options := f.begin(t, "login")
		f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": a.assertion(t, options, f.origin, passkeyTestRP, 5, counter)}, nil, 200)
	}
}
