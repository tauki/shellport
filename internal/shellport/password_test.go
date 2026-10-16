package shellport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const changedTestPassword = "synthetic-new-app-password"

func passwordInput(old, next string) map[string]string {
	return map[string]string{"currentPassword": old, "password": next, "confirmPassword": next}
}

func TestPasswordChangePersistsRevokesDevicesAndKeepsPasskeys(t *testing.T) {
	f := newPasskeyFixture(t)
	a := newTestAuthenticator(t)
	record := f.register(t, a)
	device := *f.cookies[cookieName]
	f.password(t)
	current := *f.cookies[cookieName]
	before, err := os.ReadFile(filepath.Join(f.store.Dir, "passkeys.json"))
	if err != nil {
		t.Fatal(err)
	}
	host := Host{Name: "Example", Address: "server.example.test", Port: 22, Username: "demo", Auth: "key"}
	f.call(t, "POST", "/api/hosts", host, nil, 200)
	hostBefore, _ := os.ReadFile(filepath.Join(f.store.Dir, "hosts.json"))
	keyBefore, _ := os.ReadFile(f.store.Config.KeyFile)
	// A successful verification already in flight cannot mint an old-password login after rotation.
	oldHash, ok := f.app.auth.verifyPassword(httptest.NewRecorder(), httptest.NewRequest("POST", passkeyTestOrigin+"/api/login", nil), testPassword, passwordLoginAttempt)
	if !ok {
		t.Fatal("fixture verification")
	}
	f.call(t, "POST", "/api/password", passwordInput(testPassword, changedTestPassword), nil, 200)
	if f.cookies[cookieName] != nil {
		t.Fatal("changing device remained signed in")
	}
	for _, cookie := range []*http.Cookie{&device, &current} {
		f.cookies[cookieName] = cookie
		f.call(t, "GET", "/api/passkeys", nil, nil, 401)
	}
	delete(f.cookies, cookieName)
	req := httptest.NewRequest("POST", passkeyTestOrigin+"/api/login", nil)
	res := httptest.NewRecorder()
	if f.app.auth.issueWithPassword(res, req, oldHash) || res.Code != 401 {
		t.Fatal("stale password verification signed in")
	}
	f.call(t, "POST", "/api/login", map[string]string{"password": testPassword}, nil, 401)
	f.call(t, "POST", "/api/login", map[string]string{"password": changedTestPassword}, nil, 200)
	after, _ := os.ReadFile(filepath.Join(f.store.Dir, "passkeys.json"))
	hostAfter, _ := os.ReadFile(filepath.Join(f.store.Dir, "hosts.json"))
	keyAfter, _ := os.ReadFile(f.store.Config.KeyFile)
	if !bytes.Equal(before, after) || !bytes.Equal(hostBefore, hostAfter) || !bytes.Equal(keyBefore, keyAfter) || f.store.passkeySummaries(passkeyTestRP)[0].ID != record.ID {
		t.Fatal("password change replaced private data")
	}
	stat, _ := os.Stat(filepath.Join(f.store.Dir, "config.json"))
	if stat.Mode().Perm() != 0600 {
		t.Fatal("public config")
	}
	data, _ := os.ReadFile(filepath.Join(f.store.Dir, "config.json"))
	if bytes.Contains(data, []byte(changedTestPassword)) {
		t.Fatal("plaintext password persisted")
	}
	reopened, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	newApp := NewServer(reopened, nil)
	defer newApp.Close()
	f.app = newApp
	f.call(t, "POST", "/api/login", map[string]string{"password": testPassword}, nil, 401)
	f.call(t, "POST", "/api/login", map[string]string{"password": changedTestPassword}, nil, 200)
	f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
	options := f.begin(t, "login")
	f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": a.assertion(t, options, f.origin, passkeyTestRP, 5, 1)}, nil, 200)
}

func TestPasswordChangeValidationAndWriteFailurePreserveAccess(t *testing.T) {
	f := newPasskeyFixture(t)
	f.call(t, "POST", "/api/password", passwordInput(testPassword, changedTestPassword), nil, 401)
	f.password(t)
	f.call(t, "POST", "/api/password", passwordInput("wrong", changedTestPassword), nil, 401)
	for _, next := range []string{"short", strings.Repeat("a", 73), strings.Repeat("界", 25), testPassword} {
		f.call(t, "POST", "/api/password", passwordInput(testPassword, next), nil, 400)
	}
	input := passwordInput(testPassword, changedTestPassword)
	input["confirmPassword"] = "another-password"
	f.call(t, "POST", "/api/password", input, nil, 400)
	originalHash := f.store.Config.PasswordHash
	dir := f.store.Dir
	f.store.Dir = filepath.Join(dir, "missing")
	f.call(t, "POST", "/api/password", passwordInput(testPassword, changedTestPassword), nil, 500)
	f.store.Dir = dir
	if f.app.auth.hash != originalHash || f.store.Config.PasswordHash != originalHash {
		t.Fatal("failed save changed the password")
	}
	f.call(t, "GET", "/api/hosts", nil, nil, 200)
	f.password(t)
}

func TestConcurrentPasswordChangesCommitOnlyOnce(t *testing.T) {
	f := newPasskeyFixture(t)
	f.password(t)
	cookie := *f.cookies[cookieName]
	var group sync.WaitGroup
	codes := make(chan int, 2)
	for _, password := range []string{changedTestPassword, "another-synthetic-password"} {
		group.Add(1)
		go func(next string) {
			defer group.Done()
			data, _ := json.Marshal(passwordInput(testPassword, next))
			req := httptest.NewRequest("POST", passkeyTestOrigin+"/api/password", bytes.NewReader(data))
			req.Header.Set("Origin", passkeyTestOrigin)
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&cookie)
			res := httptest.NewRecorder()
			f.app.ServeHTTP(res, req)
			codes <- res.Code
		}(password)
	}
	group.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 200 {
			success++
		} else if code != 401 {
			t.Fatal("unexpected concurrent result", code)
		}
	}
	if success != 1 {
		t.Fatal("multiple password changes committed")
	}
}

func TestPasskeyRenamePreservesCredentialAndDoesNotRequirePasswordRefresh(t *testing.T) {
	f := newPasskeyFixture(t)
	a := newTestAuthenticator(t)
	record := f.register(t, a)
	original := copyPasskeyState(f.store.passkeys)
	owner := f.cookies[cookieName].Value
	f.app.auth.mu.Lock()
	session := f.app.auth.cookies[owner]
	session.verified = time.Now().Add(-recentAuthTTL - time.Second)
	f.app.auth.cookies[owner] = session
	f.app.auth.mu.Unlock()
	for _, name := range []string{"", strings.Repeat("a", 81), "bad\nname"} {
		f.call(t, "PATCH", "/api/passkeys/"+record.ID, map[string]string{"name": name}, nil, 400)
	}
	f.call(t, "PATCH", "/api/passkeys/"+record.ID, map[string]string{"name": "Personal phone"}, nil, 200)
	renamed := copyPasskeyState(f.store.passkeys)
	renamed.Keys[0].Name = original.Keys[0].Name
	left, _ := json.Marshal(original)
	right, _ := json.Marshal(renamed)
	if !bytes.Equal(left, right) {
		t.Fatal("rename replaced credential metadata")
	}
	reopened, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.passkeySummaries(passkeyTestRP)[0].Name != "Personal phone" {
		t.Fatal("rename not persisted")
	}
	f.call(t, "POST", "/api/logout", struct{}{}, nil, 200)
	f.call(t, "PATCH", "/api/passkeys/"+record.ID, map[string]string{"name": "unauthenticated"}, nil, 401)
	options := f.begin(t, "login")
	f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": a.assertion(t, options, f.origin, passkeyTestRP, 5, 1)}, nil, 200)
}

func TestPasswordChangeDisconnectsDevicesAndPreservesTmuxWork(t *testing.T) {
	f := newFixture(t)
	f.store.Config.AllowLocalShell = true
	f.store.Config.TmuxExecutable = testTmux(t)
	f.login(t)
	host, err := f.store.SaveHost(Host{Name: "Fixture", Address: "127.0.0.1", Port: 22, Username: "demo", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	first, reply := connectShellTab(t, f, host, map[string]any{"session": "password-proof", "create": true})
	terminalCommand(t, first, "PASSWORD_PROOF=preserved; printf 'PROOF_%s\\n' \"$PASSWORD_PROOF\"", "PROOF_preserved\r\n")
	originalClient := f.client
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
	f.login(t)
	second, _ := connectShellTab(t, f, host, map[string]any{"session": reply.Session, "sessionRef": reply.SessionRef, "newWindow": true})
	if code := f.call(t, "POST", "/api/password", passwordInput(testPassword, changedTestPassword), nil); code != 200 {
		t.Fatal(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, socket := range []*websocket.Conn{first, second} {
		for {
			_, _, err = socket.Read(ctx)
			if err != nil {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("password change left a terminal connected")
		}
	}
	f.client = originalClient
	if code := f.call(t, "GET", "/api/hosts", nil, nil); code != 401 {
		t.Fatal("other device stayed signed in", code)
	}
	if code := f.call(t, "POST", "/api/login", map[string]string{"password": changedTestPassword}, nil); code != 200 {
		t.Fatal(code)
	}
	resumed, _ := connectShellTab(t, f, host, map[string]any{"session": reply.Session, "sessionRef": reply.SessionRef, "window": reply.Window.ID})
	terminalCommand(t, resumed, "printf 'RESUMED_%s\\n' \"$PASSWORD_PROOF\"", "RESUMED_preserved\r\n")
}
