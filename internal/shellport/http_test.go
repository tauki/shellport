package shellport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHTTPReadTimeoutClosesStalledBodies(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, method, path, contentType, body string
		chunked, trickle, wrongOrigin         bool
		status                                int
	}{
		{name: "incomplete-login", body: `{"password":`, status: 400},
		{name: "login-awaits-eof", body: `{"password":"synthetic-test-password"}`, status: 400},
		{name: "chunked-login-awaits-eof", body: `{"password":"synthetic-test-password"}`, chunked: true, status: 400},
		{name: "trickled-login", body: `{"password":`, trickle: true, status: 400},
		{name: "passkey-awaits-eof", path: "/api/passkeys/login/begin", body: "{}", status: 400},
		{name: "malformed-json-drain", body: "!", status: 400},
		{name: "unknown-field-drain", body: `{"unknown":true}`, status: 400},
		{name: "content-type-drain", contentType: "text/plain", body: "!", status: 415},
		{name: "origin-rejection-drain", body: "!", wrongOrigin: true, status: 403},
		{name: "authentication-rejection-drain", path: "/api/hosts", body: "!", status: 401},
		{name: "passkey-flow-rejection-drain", path: "/api/passkeys/login/finish", body: "!", status: 400},
		{name: "health-drain", method: "GET", path: "/api/health", body: "!", status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			budget := f.http.Config.ReadTimeout
			if budget != 10*time.Second {
				t.Fatalf("production request-read budget = %s", budget)
			}
			conn, err := net.Dial("tcp", f.http.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			start := time.Now()
			if err := conn.SetDeadline(start.Add(budget + 3*time.Second)); err != nil {
				t.Fatal(err)
			}
			method, path, contentType, origin := tc.method, tc.path, tc.contentType, f.http.URL
			if method == "" {
				method = "POST"
			}
			if path == "" {
				path = "/api/login"
			}
			if contentType == "" {
				contentType = "application/json"
			}
			if tc.wrongOrigin {
				origin = "http://evil.example"
			}
			framing := fmt.Sprintf("Content-Length: %d\r\n", len(tc.body)+128)
			body := tc.body
			if tc.chunked {
				framing = "Transfer-Encoding: chunked\r\n"
				body = fmt.Sprintf("%x\r\n%s\r\n", len(body), body) // Deliberately omit the terminal chunk.
			}
			request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: %s\r\n%s\r\n%s",
				method, path, f.http.Listener.Addr(), origin, contentType, framing, body)
			if _, err := io.WriteString(conn, request); err != nil {
				t.Fatal(err)
			}
			if tc.trickle {
				stop, done := make(chan struct{}), make(chan struct{})
				defer func() { close(stop); <-done }()
				go func() {
					defer close(done)
					ticker := time.NewTicker(250 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-stop:
							return
						case <-ticker.C:
							if _, err := io.WriteString(conn, " "); err != nil {
								return
							}
						}
					}
				}()
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal("stalled request did not return a bounded response", err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, tc.status)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal("response body", err)
			}
			response.Body.Close()
			if _, err := reader.ReadByte(); err != io.EOF && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("stalled connection was not closed: %v", err)
			}
			t.Logf("stalled connection closed after %s", time.Since(start))
		})
	}
}

func TestHTTPReadTimeoutPreservesKeepAliveAndJSON(t *testing.T) {
	f := newFixture(t)
	_, port, err := net.SplitHostPort(f.http.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	passkeyHost := net.JoinHostPort("localhost", port)
	passkeyOrigin := "http://" + passkeyHost
	f.app.auth.origins[passkeyOrigin] = true
	conn, err := net.Dial("tcp", f.http.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	body := `{"password":"synthetic-test-password"}`
	request := fmt.Sprintf("POST /api/login HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		f.http.Listener.Addr(), f.http.URL, len(body), body)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || len(response.Cookies()) == 0 {
		t.Fatal("valid login failed", response.StatusCode)
	}
	cookie := response.Cookies()[0]
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	// The idle keep-alive connection must outlive the request-read budget.
	<-time.After(f.http.Config.ReadTimeout + 100*time.Millisecond)
	if _, err := fmt.Fprintf(conn, "GET /api/me HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\n\r\n",
		f.http.Listener.Addr(), cookie.Name, cookie.Value); err != nil {
		t.Fatal(err)
	}
	response, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal("keep-alive request after read budget", err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(data), `"authenticated":true`) {
		t.Fatal("keep-alive lost authentication", response.StatusCode, string(data), err)
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"unknown":true}`, 400},
		{`{} {}`, 400},
		{`{"password":"` + strings.Repeat("x", 64<<10) + `"}`, 400},
	} {
		req, err := http.NewRequest("POST", f.http.URL+"/api/login", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", f.http.URL)
		req.Header.Set("Content-Type", "application/json")
		res, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Fatalf("JSON validation = %d, want %d", res.StatusCode, tc.want)
		}
	}
	req, err := http.NewRequest("POST", f.http.URL+"/api/passkeys/login/begin", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = passkeyHost
	req.Header.Set("Origin", passkeyOrigin)
	req.Header.Set("Content-Type", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("valid passkey begin = %d", res.StatusCode)
	}
}
