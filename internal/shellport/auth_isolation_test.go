package shellport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkbenchAuthenticationIsolation(t *testing.T) {
	f := newPasskeyFixture(t)
	call := func(client, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", passkeyTestOrigin+path, strings.NewReader(body))
		r.RemoteAddr = client
		r.Header.Set("Origin", passkeyTestOrigin)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		f.app.ServeHTTP(w, r)
		return w
	}
	initial := call("192.0.2.2:1234", "/api/login", "{\"password\":\""+testPassword+"\"}", nil)
	if initial.Code != 200 {
		t.Fatalf("legitimate control: %d", initial.Code)
	}
	var owner *http.Cookie
	for _, c := range initial.Result().Cookies() {
		if c.Name == cookieName {
			owner = c
		}
	}
	for range 10 {
		call("192.0.2.1:1234", "/api/login", "{\"password\":\"wrong\"}", nil)
	}
	for _, tc := range []struct {
		path, body string
		cookie     *http.Cookie
	}{
		{"/api/login", "{\"password\":\"" + testPassword + "\"}", nil},
		{"/api/passkeys/login/begin", "{}", nil},
		{"/api/passkeys/confirm", "{\"password\":\"" + testPassword + "\"}", owner},
	} {
		if w := call("192.0.2.2:4321", tc.path, tc.body, tc.cookie); w.Code != 200 {
			t.Errorf("ten attacker requests blocked legitimate %s: status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
	}
}
