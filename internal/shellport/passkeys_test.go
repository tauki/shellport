package shellport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const passkeyTestOrigin = "https://shellport.example.test"
const passkeyTestRP = "shellport.example.test"

type passkeyFixture struct {
	app     *Server
	store   *Store
	cookies map[string]*http.Cookie
	origin  string
}
type testPasskeyOptions struct {
	Options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Selection        struct{ ResidentKey, UserVerification string } `json:"authenticatorSelection"`
			UserVerification string                                         `json:"userVerification"`
		}
	} `json:"options"`
	NeedsPassword bool `json:"needsPassword"`
}

func newPasskeyFixture(t *testing.T) *passkeyFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{passkeyTestOrigin, "https://other.example.test"}, ""); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	app := NewServer(store, nil)
	t.Cleanup(app.Close)
	return &passkeyFixture{app: app, store: store, cookies: map[string]*http.Cookie{}, origin: passkeyTestOrigin}
}
func (f *passkeyFixture) call(t *testing.T, method, path string, input, out any, want int) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, f.origin+path, bytes.NewReader(data))
	req.Header.Set("Origin", f.origin)
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range f.cookies {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	f.app.ServeHTTP(response, req)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(f.cookies, cookie.Name)
		} else {
			f.cookies[cookie.Name] = cookie
		}
	}
	if response.Code != want {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, response.Code, want, response.Body.String())
	}
	if out != nil {
		if err = json.Unmarshal(response.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	return response
}
func (f *passkeyFixture) password(t *testing.T) {
	f.call(t, "POST", "/api/login", map[string]string{"password": testPassword}, nil, 200)
}
func (f *passkeyFixture) begin(t *testing.T, kind string) testPasskeyOptions {
	t.Helper()
	var options testPasskeyOptions
	f.call(t, "POST", "/api/passkeys/"+kind+"/begin", struct{}{}, &options, 200)
	return options
}

type testAuthenticator struct {
	key  *ecdsa.PrivateKey
	id   []byte
	user []byte
}

func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthenticator{key: key, id: []byte(randomID())}
}
func encoded(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func clientData(kind, challenge, origin string) []byte {
	value, _ := json.Marshal(map[string]any{"type": "webauthn." + kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return value
}
func authData(rp string, flags byte, counter uint32) []byte {
	hash := sha256.Sum256([]byte(rp))
	data := make([]byte, 37)
	copy(data, hash[:])
	data[32] = flags
	binary.BigEndian.PutUint32(data[33:], counter)
	return data
}
func (a *testAuthenticator) registration(t *testing.T, options testPasskeyOptions, origin, rp string, flags byte) map[string]any {
	t.Helper()
	a.user, _ = base64.RawURLEncoding.DecodeString(options.Options.PublicKey.User.ID)
	key, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	data := authData(rp, flags|0x40, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.id)))
	data = append(data, a.id...)
	data = append(data, key...)
	object, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "authData": data, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": encoded(a.id), "rawId": encoded(a.id), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": true}}, "response": map[string]any{"clientDataJSON": encoded(clientData("create", options.Options.PublicKey.Challenge, origin)), "attestationObject": encoded(object), "transports": []string{"internal"}}}
}
func (a *testAuthenticator) assertion(t *testing.T, options testPasskeyOptions, origin, rp string, flags byte, counter uint32) map[string]any {
	t.Helper()
	client := clientData("get", options.Options.PublicKey.Challenge, origin)
	data := authData(rp, flags, counter)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, data...), clientHash[:]...)
	hash := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": encoded(a.id), "rawId": encoded(a.id), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": encoded(client), "authenticatorData": encoded(data), "signature": encoded(signature), "userHandle": encoded(a.user)}}
}
func (f *passkeyFixture) register(t *testing.T, a *testAuthenticator) passkeySummary {
	t.Helper()
	f.password(t)
	options := f.begin(t, "register")
	if options.Options.PublicKey.Selection.ResidentKey != "required" || options.Options.PublicKey.Selection.UserVerification != "required" || options.Options.PublicKey.RP.ID != passkeyTestRP {
		t.Fatal("unsafe registration options")
	}
	var result passkeySummary
	f.call(t, "POST", "/api/passkeys/register/finish", map[string]any{"name": "My phone", "credential": a.registration(t, options, f.origin, passkeyTestRP, 5)}, &result, 200)
	return result
}

func TestPasskeyLifecyclePersistenceAndPasswordFallback(t *testing.T) {
	f := newPasskeyFixture(t)
	if _, err := os.Stat(filepath.Join(f.store.Dir, "passkeys.json")); !os.IsNotExist(err) {
		t.Fatal("startup created passkey state")
	}
	f.call(t, "GET", "/api/passkeys", nil, nil, 401)
	f.call(t, "POST", "/api/passkeys/register/begin", struct{}{}, nil, 401)
	if !f.begin(t, "login").NeedsPassword {
		t.Fatal("new install needs password setup")
	}
	if _, err := os.Stat(filepath.Join(f.store.Dir, "passkeys.json")); !os.IsNotExist(err) {
		t.Fatal("public login created passkey state")
	}
	a := newTestAuthenticator(t)
	record := f.register(t, a)
	info, err := os.Stat(filepath.Join(f.store.Dir, "passkeys.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("passkey storage is not private", err)
	}
	reopened, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	f.store = reopened
	f.app.store = reopened
	f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
	options := f.begin(t, "login")
	if options.Options.PublicKey.UserVerification != "required" {
		t.Fatal("verification optional")
	}
	flow := *f.cookies[passkeyCookie("login")]
	assertion := a.assertion(t, options, f.origin, passkeyTestRP, 5, 1)
	response := f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": assertion}, nil, 200)
	session := f.cookies[cookieName]
	if session == nil || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe login cookie", response.Header())
	}
	var directory struct{ Passkeys []passkeySummary }
	res := f.call(t, "GET", "/api/passkeys", nil, &directory, 200)
	if len(directory.Passkeys) != 1 || directory.Passkeys[0].LastUsedAt == nil || !directory.Passkeys[0].AvailableHere || strings.Contains(res.Body.String(), "publicKey") || strings.Contains(res.Body.String(), "userId") {
		t.Fatal("wrong public metadata", res.Body.String())
	}
	f.cookies[passkeyCookie("login")] = &flow
	f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": assertion}, nil, 400)
	f.call(t, "DELETE", "/api/passkeys/"+record.ID, map[string]bool{"confirm": false}, nil, 400)
	f.call(t, "DELETE", "/api/passkeys/"+record.ID, map[string]bool{"confirm": true}, nil, 200)
	f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
	if !f.begin(t, "login").NeedsPassword {
		t.Fatal("removed credential still offered")
	}
	f.password(t)
}

func TestPasskeyRegistrationRejectsWrongClaimsAndReplays(t *testing.T) {
	for _, scenario := range []string{"origin", "rp", "challenge", "uv", "presence", "logout", "different-owner", "expired", "unsolicited-extension"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPasskeyFixture(t)
			f.password(t)
			options := f.begin(t, "register")
			a := newTestAuthenticator(t)
			origin, rp, flags := f.origin, passkeyTestRP, byte(5)
			switch scenario {
			case "origin":
				origin = "https://evil.example.test"
			case "rp":
				rp = "other.example.test"
			case "challenge":
				options.Options.PublicKey.Challenge = encoded([]byte("different challenge"))
			case "uv":
				flags = 1
			case "presence":
				flags = 4
			}
			credential := a.registration(t, options, origin, rp, flags)
			flow := *f.cookies[passkeyCookie("register")]
			want := 400
			switch scenario {
			case "logout":
				f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
				want = 401
			case "different-owner":
				f.password(t)
			case "expired":
				f.app.passkeys.mu.Lock()
				entry := f.app.passkeys.flows[flow.Value]
				entry.expires = time.Now().Add(-time.Second)
				f.app.passkeys.flows[flow.Value] = entry
				f.app.passkeys.mu.Unlock()
			case "unsolicited-extension":
				credential["clientExtensionResults"] = map[string]any{"appid": true}
			}
			f.call(t, "POST", "/api/passkeys/register/finish", map[string]any{"credential": credential}, nil, want)
			if len(f.store.passkeySummaries(passkeyTestRP)) != 0 {
				t.Fatal("bad registration saved")
			}
			if scenario != "logout" {
				f.cookies[passkeyCookie("register")] = &flow
				f.call(t, "POST", "/api/passkeys/register/finish", map[string]any{"credential": credential}, nil, 400)
			}
		})
	}
}

func TestPasskeyLoginRejectsInvalidAssertions(t *testing.T) {
	for _, scenario := range []string{"origin", "rp", "challenge", "uv", "signature", "user-handle", "unknown-key", "expired", "revoked", "counter"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPasskeyFixture(t)
			a := newTestAuthenticator(t)
			record := f.register(t, a)
			options := f.begin(t, "login")
			origin, rp, flags := f.origin, passkeyTestRP, byte(5)
			switch scenario {
			case "origin":
				origin = "https://evil.example.test"
			case "rp":
				rp = "other.example.test"
			case "challenge":
				options.Options.PublicKey.Challenge = encoded([]byte("wrong"))
			case "uv":
				flags = 1
			}
			credential := a.assertion(t, options, origin, rp, flags, 1)
			response := credential["response"].(map[string]any)
			want := 401
			switch scenario {
			case "signature":
				response["signature"] = encoded([]byte("forged"))
			case "user-handle":
				response["userHandle"] = encoded([]byte("other user"))
			case "unknown-key":
				credential["id"] = encoded([]byte("unknown"))
				credential["rawId"] = credential["id"]
			case "expired":
				flow := f.cookies[passkeyCookie("login")].Value
				f.app.passkeys.mu.Lock()
				entry := f.app.passkeys.flows[flow]
				entry.expires = time.Now().Add(-time.Second)
				f.app.passkeys.flows[flow] = entry
				f.app.passkeys.mu.Unlock()
				want = 400
			case "revoked":
				f.call(t, "DELETE", "/api/passkeys/"+record.ID, map[string]bool{"confirm": true}, nil, 200)
			case "counter":
				f.store.mu.Lock()
				f.store.passkeys.Keys[0].Credential.Authenticator.SignCount = 2
				f.store.mu.Unlock()
			}
			f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
			f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": credential}, nil, want)
			f.call(t, "GET", "/api/hosts", nil, nil, 401)
		})
	}
}

func TestPasskeyOriginPartitionAndFreshAuthentication(t *testing.T) {
	f := newPasskeyFixture(t)
	a := newTestAuthenticator(t)
	record := f.register(t, a)
	f.origin = "https://other.example.test"
	if !f.begin(t, "login").NeedsPassword {
		t.Fatal("sibling RP offered credential")
	}
	f.origin = passkeyTestOrigin
	flowOptions := f.begin(t, "login")
	f.origin = "https://other.example.test"
	f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": a.assertion(t, flowOptions, passkeyTestOrigin, passkeyTestRP, 5, 1)}, nil, 400)
	f.origin = passkeyTestOrigin
	owner := f.cookies[cookieName].Value
	f.app.auth.mu.Lock()
	session := f.app.auth.cookies[owner]
	expires := session.expires
	session.verified = time.Now().Add(-recentAuthTTL - time.Second)
	f.app.auth.cookies[owner] = session
	f.app.auth.mu.Unlock()
	f.call(t, "POST", "/api/passkeys/register/begin", struct{}{}, nil, 403)
	f.call(t, "DELETE", "/api/passkeys/"+record.ID, map[string]bool{"confirm": true}, nil, 403)
	f.call(t, "POST", "/api/passkeys/confirm", map[string]string{"password": "wrong"}, nil, 401)
	f.call(t, "POST", "/api/passkeys/confirm", map[string]string{"password": testPassword}, nil, 200)
	if !f.app.auth.recent(owner) || f.app.auth.expiry(owner) != expires || f.cookies[cookieName].Value != owner {
		t.Fatal("reauth changed session or failed")
	}
	f.call(t, "DELETE", "/api/passkeys/"+record.ID, map[string]bool{"confirm": true}, nil, 200)
}

func TestPasskeyOriginsAndBoundedFlows(t *testing.T) {
	for _, origin := range []string{"https://shellport.example.test", "http://localhost:8088"} {
		if _, _, err := passkeyEngine(origin); err != nil {
			t.Fatal(origin, err)
		}
	}
	for _, origin := range []string{"http://shellport.example.test", "https://127.0.0.1:8088", "https://", "not a url"} {
		if _, _, err := passkeyEngine(origin); err == nil {
			t.Fatal("unsafe RP", origin)
		}
	}
	f := newPasskeyFixture(t)
	f.password(t)
	f.begin(t, "register")
	cookie := f.cookies[passkeyCookie("register")]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/passkeys" {
		t.Fatal("unsafe challenge cookie")
	}
	f.begin(t, "register")
	if len(f.app.passkeys.flows) != 1 {
		t.Fatal("same client accumulated flows")
	}
	for i := 0; i < 128; i++ {
		f.app.passkeys.flows[randomID()] = passkeyFlow{expires: time.Now().Add(time.Minute)}
	}
	f.call(t, "POST", "/api/passkeys/register/begin", struct{}{}, nil, 429)
	req := httptest.NewRequest("POST", passkeyTestOrigin+"/api/passkeys/login/begin", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	res := httptest.NewRecorder()
	f.app.ServeHTTP(res, req)
	if res.Code != 403 {
		t.Fatal("cross-origin login allowed")
	}
}

func TestPasskeyPersistenceFailureAndConcurrentDuplicate(t *testing.T) {
	f := newPasskeyFixture(t)
	a := newTestAuthenticator(t)
	f.register(t, a)
	user, err := f.store.passkeyUser(passkeyTestRP, false)
	if err != nil {
		t.Fatal(err)
	}
	credential := user.credentials[0]
	// Independent callers cannot save the same authenticator twice.
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := f.store.addPasskey(passkeyTestRP, "Duplicate", credential); err == nil {
				t.Error("duplicate accepted")
			}
		}()
	}
	group.Wait()
	if len(f.store.passkeySummaries(passkeyTestRP)) != 1 {
		t.Fatal("duplicate persisted")
	}
	// A disk failure must leave the last usable in-memory credential intact.
	dir := f.store.Dir
	f.store.Dir = filepath.Join(dir, "missing")
	if err = f.store.removePasskey(f.store.passkeySummaries(passkeyTestRP)[0].ID); err == nil {
		t.Fatal("disk failure ignored")
	}
	f.store.Dir = dir
	if len(f.store.passkeySummaries(passkeyTestRP)) != 1 {
		t.Fatal("failed write changed state")
	}
	if err = os.Chmod(filepath.Join(dir, "passkeys.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenStore(dir); err == nil {
		t.Fatal("public passkey file accepted")
	}
}

func TestPasskeyManagementRejectsExpiryAtCommit(t *testing.T) {
	f := newPasskeyFixture(t)
	f.password(t)
	owner := f.cookies[cookieName].Value
	f.app.auth.mu.Lock()
	session := f.app.auth.cookies[owner]
	session.expires = time.Now().Add(-time.Second)
	f.app.auth.cookies[owner] = session
	f.app.auth.mu.Unlock()
	changed := false
	response := httptest.NewRecorder()
	err := f.app.auth.changePasskeys(response, owner, func() error { changed = true; return nil })
	if err != errPasskeyAuth || changed || response.Code != 401 {
		t.Fatal("expired owner changed passkeys")
	}
}
