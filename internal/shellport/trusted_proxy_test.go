package shellport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTrustedProxyFixture(t *testing.T) *passkeyFixture {
	t.Helper()
	f := newPasskeyFixture(t)
	data, err := json.Marshal(f.store.Configuration())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["trustedProxies"] = []string{"127.0.0.1", "::1"}
	if err = writePrivate(filepath.Join(f.store.Dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	f.store, err = OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	f.app = NewServer(f.store, nil)
	t.Cleanup(f.app.Close)
	return f
}

func trustedProxyCall(f *passkeyFixture, client, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8088"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", passkeyTestOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-For", client)
	r.Header.Set("X-Forwarded-Host", passkeyTestRP)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Forwarded", "for="+client+";proto=https")
	r.Header.Set("X-Real-IP", client)
	r.Header.Set("X-Forwarded-Port", "443")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, r)
	return w
}

func TestTrustedProxyWithoutSharedTokenIsolation(t *testing.T) {
	f := newTrustedProxyFixture(t)
	authenticator := newTestAuthenticator(t)
	f.register(t, authenticator)
	password := `{"password":"` + testPassword + `"}`
	initial := trustedProxyCall(f, "192.0.2.2", "/api/login", password, nil)
	if initial.Code != 200 {
		t.Fatalf("trusted proxy without a shared token: %d %s", initial.Code, initial.Body.String())
	}
	owner := initial.Result().Cookies()[0]
	if !owner.Secure || !owner.HttpOnly || owner.SameSite != http.SameSiteStrictMode {
		t.Fatal("proxied HTTPS sign-in lost secure cookie properties")
	}
	challenge := trustedProxyCall(f, "192.0.2.2", "/api/passkeys/login/begin", "{}", nil)
	if challenge.Code != 200 {
		t.Fatal("proxied passkey challenge", challenge.Code, challenge.Body.String())
	}
	var options testPasskeyOptions
	if err := json.Unmarshal(challenge.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(map[string]any{"credential": authenticator.assertion(t, options, passkeyTestOrigin, passkeyTestRP, 5, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if w := trustedProxyCall(f, "192.0.2.2", "/api/passkeys/login/finish", string(credential), challenge.Result().Cookies()[0]); w.Code != 200 {
		t.Fatal("proxied passkey authentication", w.Code, w.Body.String())
	}
	for range 10 {
		w := trustedProxyCall(f, "192.0.2.1", "/api/login", `{"password":"wrong"}`, nil)
		if w.Code != 401 {
			t.Fatal("wrong password", w.Code, w.Body.String())
		}
	}
	if w := trustedProxyCall(f, "::ffff:192.0.2.1", "/api/login", password, nil); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("mapped alias bypassed the attacking client's budget", w.Code)
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
		w := trustedProxyCall(f, tc.client, tc.path, tc.body, tc.cookie)
		if w.Code != 200 {
			t.Fatalf("%s from %s: %d %s", tc.path, tc.client, w.Code, w.Body.String())
		}
	}
	for range 9 {
		if w := trustedProxyCall(f, "192.0.2.1", "/api/passkeys/login/begin", `{}`, nil); w.Code != 200 {
			t.Fatal("passkey allowance", w.Code)
		}
	}
	if w := trustedProxyCall(f, "192.0.2.1", "/api/passkeys/login/begin", `{}`, nil); w.Code != 429 {
		t.Fatal("passkey challenge limit lost", w.Code)
	}
	if w := trustedProxyCall(f, "192.0.2.2", "/api/passkeys/login/begin", `{}`, nil); w.Code != 200 {
		t.Fatal("passkey client isolation lost", w.Code)
	}
	change := `{"currentPassword":"` + testPassword + `","password":"` + changedTestPassword + `","confirmPassword":"` + changedTestPassword + `"}`
	if w := trustedProxyCall(f, "192.0.2.1", "/api/password", change, owner); w.Code != 200 {
		t.Fatal("public traffic blocked signed-in password rotation", w.Code, w.Body.String())
	}
}
