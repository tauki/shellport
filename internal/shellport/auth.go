package shellport

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const cookieName = "shellport_session"
const sessionTTL = 12 * time.Hour
const recentAuthTTL = 10 * time.Minute

type authSession struct{ expires, verified time.Time }

type attemptPurpose uint8

const (
	passwordLoginAttempt attemptPurpose = iota
	passkeyLoginAttempt
	passwordConfirmationAttempt
	clientAttemptLimit = 10
	globalAttemptLimit = 100
)

type authAttempt struct {
	client  string
	at      time.Time
	pending bool
}

type auth struct {
	mu               sync.Mutex
	cookies          map[string]authSession
	attempts         [3][]*authAttempt
	hash             string
	origins          map[string]bool
	trustedProxies   []netip.Prefix
	proxyConfigValid bool
}

func newAuth(cfg Config) *auth {
	a := &auth{cookies: map[string]authSession{}, hash: cfg.PasswordHash, origins: map[string]bool{}}
	var err error
	a.trustedProxies, err = parseTrustedProxies(cfg.TrustedProxies)
	a.proxyConfigValid = err == nil
	for _, o := range cfg.Origins {
		a.origins[o] = true
	}
	return a
}

func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	proxies := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		if err == nil {
			if ip.Zone() != "" {
				return nil, fmt.Errorf("trustedProxies must not contain zone identifiers: %q", value)
			}
			ip = ip.Unmap()
			if ip.IsUnspecified() || ip.IsMulticast() {
				return nil, fmt.Errorf("trustedProxies contains an invalid proxy IP: %q", value)
			}
			proxies = append(proxies, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("trustedProxies must contain numeric IP addresses or CIDRs: %q", value)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("use an IPv4 CIDR for mapped proxy addresses: %q", value)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}

func (a *auth) trustedProxy(ip netip.Addr) bool {
	for _, proxy := range a.trustedProxies {
		if proxy.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve identity and origin at the same boundary. Proxy IP trust also trusts
// other processes able to connect from that IP.
func (a *auth) requestIdentity(r *http.Request) (string, string, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || peer.Addr().Zone() != "" || !a.proxyConfigValid {
		return "", "", false
	}
	ip := peer.Addr().Unmap()
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	// X-Forwarded-For is the only client-IP source. A proxy may also emit other
	// formats; never interpret them or fall back after malformed/missing XFF.
	forwarded := false
	for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "Forwarded"} {
		forwarded = forwarded || len(r.Header.Values(header)) != 0
	}
	if !forwarded {
		return ip.String(), scheme + "://" + host, true
	}
	addresses := r.Header.Values("X-Forwarded-For")
	if !a.trustedProxy(ip) || len(addresses) != 1 {
		return "", "", false
	}
	ip, err = netip.ParseAddr(addresses[0])
	if err != nil || ip.Zone() != "" {
		return "", "", false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() {
		return "", "", false
	}
	hosts := r.Header.Values("X-Forwarded-Host")
	schemes := r.Header.Values("X-Forwarded-Proto")
	if len(hosts) != 0 || len(schemes) != 0 {
		if len(hosts) != 1 || len(schemes) != 1 || (schemes[0] != "http" && schemes[0] != "https") || strings.ContainsAny(hosts[0], ", \t\r\n/\\?#@") {
			return "", "", false
		}
		u, err := url.Parse("//" + hosts[0])
		if err != nil || u.Host != hosts[0] || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return "", "", false
		}
		host, scheme = hosts[0], schemes[0]
	}
	return ip.String(), scheme + "://" + host, true
}

func (a *auth) client(r *http.Request) (string, bool) {
	client, _, ok := a.requestIdentity(r)
	return client, ok
}

func (a *auth) origin(r *http.Request) string {
	_, origin, _ := a.requestIdentity(r)
	return origin
}

func (a *auth) allowed(r *http.Request, write bool) bool {
	_, origin, ok := a.requestIdentity(r)
	if !ok {
		return false
	}
	if !a.origins[origin] {
		return false
	}
	supplied := r.Header.Get("Origin")
	if write {
		return supplied == origin
	}
	return supplied == "" || supplied == origin
}

func (a *auth) owner(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.cookies[c.Value]
	if !ok || time.Now().After(session.expires) {
		delete(a.cookies, c.Value)
		return ""
	}
	return c.Value
}

func (a *auth) expiry(owner string) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cookies[owner].expires
}

func (a *auth) allowAttempt(w http.ResponseWriter, r *http.Request, purpose attemptPurpose) *authAttempt {
	client, ok := a.client(r)
	if purpose == passwordConfirmationAttempt {
		client = a.owner(r)
		ok = ok && client != ""
	}
	if !ok {
		apiError(w, 401, "Sign in to Shellport first.")
		return nil
	}
	now := time.Now()
	a.mu.Lock()
	recent := a.attempts[purpose][:0]
	count := 0
	for _, attempt := range a.attempts[purpose] {
		if attempt.pending || now.Sub(attempt.at) < time.Minute {
			recent = append(recent, attempt)
			if attempt.client == client {
				count++
			}
		}
	}
	a.attempts[purpose] = recent
	if count >= clientAttemptLimit || len(recent) >= globalAttemptLimit {
		a.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		apiError(w, 429, "Try again in one minute.")
		return nil
	}
	attempt := &authAttempt{client: client, at: now, pending: true}
	a.attempts[purpose] = append(recent, attempt)
	a.mu.Unlock()
	return attempt
}

// Reserve capacity before expensive verification, including concurrent requests.
// Success refunds that reservation; failures retain a full rolling-minute charge.
func (a *auth) finishAttempt(purpose attemptPurpose, attempt *authAttempt, success bool) {
	if attempt == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if success {
		for i, current := range a.attempts[purpose] {
			if current == attempt {
				a.attempts[purpose] = append(a.attempts[purpose][:i], a.attempts[purpose][i+1:]...)
				break
			}
		}
	} else {
		attempt.at, attempt.pending = time.Now(), false
	}
}

func (a *auth) verifyPassword(w http.ResponseWriter, r *http.Request, password string, purpose attemptPurpose) (string, bool) {
	attempt := a.allowAttempt(w, r, purpose)
	if attempt == nil {
		return "", false
	}
	success := false
	defer func() { a.finishAttempt(purpose, attempt, success) }()
	if len(password) > 72 {
		apiError(w, 401, "That app password did not match.")
		return "", false
	}
	a.mu.Lock()
	hash := a.hash
	a.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		apiError(w, 401, "That app password did not match.")
		return "", false
	}
	success = true
	return hash, true
}

func (a *auth) login(w http.ResponseWriter, r *http.Request, password string) bool {
	hash, ok := a.verifyPassword(w, r, password, passwordLoginAttempt)
	return ok && a.issueWithPassword(w, r, hash)
}

func (a *auth) issue(w http.ResponseWriter, r *http.Request) bool {
	return a.issueWithPassword(w, r, "")
}

func (a *auth) issueWithPassword(w http.ResponseWriter, r *http.Request, expectedHash string) bool {
	now := time.Now()
	token := randomID()
	a.mu.Lock()
	if expectedHash != "" && expectedHash != a.hash {
		a.mu.Unlock()
		apiError(w, 401, "Your password changed. Sign in again.")
		return false
	}
	for k, session := range a.cookies {
		if now.After(session.expires) {
			delete(a.cookies, k)
		}
	}
	if len(a.cookies) >= 32 {
		a.mu.Unlock()
		apiError(w, 429, "Too many signed-in devices. Restart Shellport to clear them.")
		return false
	}
	a.cookies[token] = authSession{expires: now.Add(sessionTTL), verified: now}
	a.mu.Unlock()
	u, _ := url.Parse(a.origin(r))
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: u.Scheme == "https", SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	return true
}

func (a *auth) recent(owner string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.cookies[owner]
	return ok && time.Now().Before(session.expires) && time.Now().Before(session.verified.Add(recentAuthTTL))
}

func (a *auth) confirm(w http.ResponseWriter, r *http.Request, password string) bool {
	owner := a.owner(r)
	if owner == "" {
		respond(w, 401, map[string]string{"error": "Sign in to Shellport first.", "code": "sign_in_required"})
		return false
	}
	hash, ok := a.verifyPassword(w, r, password, passwordConfirmationAttempt)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.cookies[owner]
	if !ok || time.Now().After(session.expires) || hash != a.hash {
		respond(w, 401, map[string]string{"error": "Sign in to Shellport first.", "code": "sign_in_required"})
		return false
	}
	session.verified = time.Now()
	a.cookies[owner] = session
	return true
}

// Keep logout/expiry from racing credential changes after their final check.
func (a *auth) changePasskeys(w http.ResponseWriter, owner string, change func() error) error {
	return a.withSession(w, owner, true, change)
}

func (a *auth) withSession(w http.ResponseWriter, owner string, recent bool, change func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.cookies[owner]
	if !ok || !time.Now().Before(session.expires) {
		respond(w, 401, map[string]string{"error": "Sign in to Shellport first.", "code": "sign_in_required"})
		return errPasskeyAuth
	}
	if recent && !time.Now().Before(session.verified.Add(recentAuthTTL)) {
		respond(w, 403, map[string]string{"error": "Confirm your app password to manage passkeys.", "code": "reauth_required"})
		return errPasskeyAuth
	}
	return change()
}

func (a *auth) logout(w http.ResponseWriter, r *http.Request) string {
	owner := a.owner(r)
	a.mu.Lock()
	delete(a.cookies, owner)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.origin(r), "https://"), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	return owner
}
