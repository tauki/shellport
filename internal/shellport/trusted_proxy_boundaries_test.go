package shellport

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTrustedProxyIdentityAndOriginBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, peer, client, host, proto string
		proxies                         []string
		extra                           http.Header
		wantClient, wantOrigin          string
	}{
		{name: "ipv4", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, wantClient: "192.0.2.1"},
		{name: "mapped-ipv4", peer: "[::ffff:127.0.0.1]:10", client: "::ffff:192.0.2.1", proxies: []string{"127.0.0.1"}, wantClient: "192.0.2.1"},
		{name: "ipv6", peer: "[::1]:10", client: "2001:0db8::1", proxies: []string{"::1"}, wantClient: "2001:db8::1"},
		{name: "ipv4-cidr", peer: "127.0.0.2:10", client: "192.0.2.1", proxies: []string{"127.0.0.0/8"}, wantClient: "192.0.2.1"},
		{name: "mapped-cidr", peer: "127.0.0.2:10", client: "192.0.2.1", proxies: []string{"::ffff:127.0.0.0/104"}, wantClient: "192.0.2.1"},
		{name: "ipv6-cidr", peer: "[::1]:10", client: "192.0.2.1", proxies: []string{"::1/128"}, wantClient: "192.0.2.1"},
		{name: "no-implicit-loopback-trust", peer: "127.0.0.1:10", client: "192.0.2.1"},
		{name: "unlisted-loopback", peer: "[::1]:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}},
		{name: "untrusted-peer", peer: "192.0.2.9:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}},
		{name: "outside-cidr", peer: "192.0.3.1:10", client: "192.0.2.1", proxies: []string{"192.0.2.0/24"}},
		{name: "malformed-peer", peer: "localhost:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}},
		{name: "zone-peer", peer: "[fe80::1%lo0]:10", client: "192.0.2.1", proxies: []string{"fe80::/10"}},
		{name: "missing-ip", peer: "127.0.0.1:10", proxies: []string{"127.0.0.1"}},
		{name: "address-chain", peer: "127.0.0.1:10", client: "192.0.2.1, 192.0.2.2", proxies: []string{"127.0.0.1"}},
		{name: "duplicate-ip", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"X-Forwarded-For": {"192.0.2.2"}}},
		{name: "port", peer: "127.0.0.1:10", client: "192.0.2.1:80", proxies: []string{"127.0.0.1"}},
		{name: "zone", peer: "127.0.0.1:10", client: "fe80::1%lo0", proxies: []string{"127.0.0.1"}},
		{name: "mapped-zone", peer: "127.0.0.1:10", client: "::ffff:192.0.2.1%lo0", proxies: []string{"127.0.0.1"}},
		{name: "brackets", peer: "127.0.0.1:10", client: "[2001:db8::1]", proxies: []string{"127.0.0.1"}},
		{name: "unspecified", peer: "127.0.0.1:10", client: "0.0.0.0", proxies: []string{"127.0.0.1"}},
		{name: "mapped-unspecified", peer: "127.0.0.1:10", client: "::ffff:0.0.0.0", proxies: []string{"127.0.0.1"}},
		{name: "multicast", peer: "127.0.0.1:10", client: "ff02::1", proxies: []string{"127.0.0.1"}},
		{name: "quoted-ip", peer: "127.0.0.1:10", client: "\"192.0.2.1\"", proxies: []string{"127.0.0.1"}},
		{name: "parallel-standard-headers", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"Forwarded": {"for=192.0.2.1;proto=https"}, "X-Real-IP": {"192.0.2.1"}, "X-Forwarded-Port": {"443"}}, wantClient: "192.0.2.1"},
		{name: "secondary-headers-are-not-identity-sources", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"Forwarded": {"for=192.0.2.9;proto=http;host=evil.test"}, "X-Real-IP": {"192.0.2.9"}}, wantClient: "192.0.2.1"},
		{name: "forwarded-only-no-fallback", peer: "127.0.0.1:10", proxies: []string{"127.0.0.1"}, extra: http.Header{"Forwarded": {"for=192.0.2.1;proto=https"}}},
		{name: "malformed-xff-no-fallback", peer: "127.0.0.1:10", client: "not-an-ip", proxies: []string{"127.0.0.1"}, extra: http.Header{"Forwarded": {"for=192.0.2.1;proto=https"}}},
		{name: "parallel-headers-from-untrusted-peer", peer: "192.0.2.9:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"Forwarded": {"for=192.0.2.1;proto=https"}}},
		{name: "duplicate-host", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"X-Forwarded-Host": {passkeyTestRP}}},
		{name: "duplicate-proto", peer: "127.0.0.1:10", client: "192.0.2.1", proxies: []string{"127.0.0.1"}, extra: http.Header{"X-Forwarded-Proto": {"https"}}},
		{name: "host-chain", peer: "127.0.0.1:10", client: "192.0.2.1", host: "shellport.example.test,evil.test", proxies: []string{"127.0.0.1"}},
		{name: "host-path", peer: "127.0.0.1:10", client: "192.0.2.1", host: "shellport.example.test/path", proxies: []string{"127.0.0.1"}},
		{name: "host-userinfo", peer: "127.0.0.1:10", client: "192.0.2.1", host: "owner@shellport.example.test", proxies: []string{"127.0.0.1"}},
		{name: "host-query", peer: "127.0.0.1:10", client: "192.0.2.1", host: "shellport.example.test?x=1", proxies: []string{"127.0.0.1"}},
		{name: "proto-chain", peer: "127.0.0.1:10", client: "192.0.2.1", proto: "https,http", proxies: []string{"127.0.0.1"}},
		{name: "unsupported-proto", peer: "127.0.0.1:10", client: "192.0.2.1", proto: "ftp", proxies: []string{"127.0.0.1"}},
		{name: "nondefault-port", peer: "127.0.0.1:10", client: "192.0.2.1", host: "shellport.example.test:9443", proxies: []string{"127.0.0.1"}, wantClient: "192.0.2.1", wantOrigin: "https://shellport.example.test:9443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuth(Config{TrustedProxies: tc.proxies})
			r := httptest.NewRequest("POST", "http://127.0.0.1:8088/api/login", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.client)
			host, proto := tc.host, tc.proto
			if host == "" {
				host = passkeyTestRP
			}
			if proto == "" {
				proto = "https"
			}
			r.Header.Set("X-Forwarded-Host", host)
			r.Header.Set("X-Forwarded-Proto", proto)
			for name, values := range tc.extra {
				for _, value := range values {
					r.Header.Add(name, value)
				}
			}
			client, ok := a.client(r)
			origin := a.origin(r)
			wantOrigin := tc.wantOrigin
			if wantOrigin == "" && tc.wantClient != "" {
				wantOrigin = passkeyTestOrigin
			}
			if client != tc.wantClient || ok != (tc.wantClient != "") || origin != wantOrigin {
				t.Fatalf("got client=%q origin=%q ok=%v; want client=%q origin=%q", client, origin, ok, tc.wantClient, wantOrigin)
			}
		})
	}
}

func TestTrustedProxyDirectAccessAndOriginControls(t *testing.T) {
	f := newTrustedProxyFixture(t)
	password := "{\"password\":\"" + testPassword + "\"}"
	r := httptest.NewRequest("POST", passkeyTestOrigin+"/api/login", strings.NewReader(password))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", passkeyTestOrigin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("direct access rejected merely because loopback is trusted", w.Code)
	}
	owner := w.Result().Cookies()[0]
	for _, tc := range []struct {
		name, path, origin string
		mutate             func(http.Header)
		want               int
	}{
		{name: "authenticated-request", path: "/api/hosts", origin: passkeyTestOrigin, want: 200},
		{name: "websocket-needs-origin", path: "/api/terminals/unknown/terminal", want: 403},
		{name: "websocket-wrong-origin", path: "/api/terminals/unknown/terminal", origin: "https://evil.test", want: 403},
		{name: "origin-still-allowlisted", path: "/api/hosts", origin: "https://evil.test", mutate: func(h http.Header) { h.Set("X-Forwarded-Host", "evil.test") }, want: 403},
		{name: "missing-client", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) { h.Del("X-Forwarded-For") }, want: 403},
		{name: "missing-proto", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) { h.Del("X-Forwarded-Proto") }, want: 403},
		{name: "missing-host", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) { h.Del("X-Forwarded-Host") }, want: 403},
		{name: "alias-does-not-replace-client", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) {
			h.Del("X-Forwarded-For")
			h.Set("X-Real-IP", "192.0.2.2")
		}, want: 403},
		{name: "standard-header-does-not-replace-client", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) {
			h.Del("X-Forwarded-For")
			h.Set("Forwarded", "for=192.0.2.2;proto=https")
		}, want: 403},
		{name: "no-origin-rewrite-needed", path: "/api/hosts", origin: passkeyTestOrigin, mutate: func(h http.Header) {
			h.Del("X-Forwarded-Host")
			h.Del("X-Forwarded-Proto")
		}, want: 200},
		{name: "health-remains-public", path: "/api/health", want: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", passkeyTestOrigin+tc.path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("X-Forwarded-For", "192.0.2.2")
			r.Header.Set("X-Forwarded-Host", passkeyTestRP)
			r.Header.Set("X-Forwarded-Proto", "https")
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.mutate != nil {
				tc.mutate(r.Header)
			}
			r.AddCookie(owner)
			w := httptest.NewRecorder()
			f.app.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestTrustedProxyConfigurationValidationAndPersistence(t *testing.T) {
	f := newPasskeyFixture(t)
	for _, values := range [][]string{
		{"proxy.example.test"}, {"127.0.0.1:8088"}, {"127.0.0.1/33"},
		{"fe80::1%lo0"}, {"::ffff:127.0.0.1%lo0"}, {"0.0.0.0"}, {"ff02::1"}, {"::ffff:127.0.0.0/80"},
		{"127.0.0.1", "bad"}, {"127.0.0.1", "::1", "192.0.2.0/24", "2001:db8::/32"},
	} {
		cfg := f.store.Configuration()
		cfg.TrustedProxies = values
		if err := writePrivate(filepath.Join(f.store.Dir, "config.json"), cfg); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(f.store.Dir)
		if values[0] == "127.0.0.1" && len(values) == 4 {
			if err != nil || !reflect.DeepEqual(reopened.Configuration().TrustedProxies, values) {
				t.Fatal("valid trust configuration did not round-trip", err)
			}
			view := reopened.Configuration()
			view.TrustedProxies[0] = "192.0.2.9"
			if reopened.Configuration().TrustedProxies[0] != "127.0.0.1" {
				t.Fatal("configuration view aliases live proxy trust")
			}
			hash := reopened.Configuration().PasswordHash
			if err := reopened.changePasswordHash(hash, hash); err != nil {
				t.Fatal(err)
			}
			again, err := OpenStore(f.store.Dir)
			if err != nil || !reflect.DeepEqual(again.Configuration().TrustedProxies, values) {
				t.Fatal("password persistence lost proxy trust", err)
			}
		} else {
			if err == nil {
				t.Fatal("invalid proxy configuration accepted", values)
			}
			a := newAuth(Config{TrustedProxies: values})
			r := httptest.NewRequest("GET", passkeyTestOrigin+"/api/me", nil)
			if _, ok := a.client(r); ok {
				t.Fatal("in-memory invalid proxy configuration did not fail closed", values)
			}
		}
	}
}
