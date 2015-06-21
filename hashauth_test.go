package hashauth

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const signKey = "asdokjwp9RIKMOEW9Vrj39f8j43;oiESJG"

var opts = optionsList{
	{"nil", nil},
	{"md5", &Options{Hash: md5.New}},
	{"sha1", &Options{Hash: sha1.New}},
	{"sha256", &Options{Hash: sha256.New}},
	{"sha512", &Options{Hash: sha512.New}},
}

func TestTokenValidates(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		if !ha.Validate("login", token) {
			t.Fatalf("[%s] Encode-produced token doesn't Validate!", opt.name)
		}
	}
}

func TestTamperedTokenDoesntValidate(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		// base64 has some slop: changing something in the last 4 bytes
		// can sometimes still yield an equivalent decoded plaintext
		for i := 0; i < len(token)-4; i++ {
			token[i]++

			if ha.Validate("login", token) {
				t.Fatalf("[%s] tampered-with token still validates! (%d)", opt.name, i)
			}

			token[i]--
		}
	}
}

func TestTamperedTokenDoesntDecode(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		for i := 0; i < len(token)-4; i++ {
			token[i]++

			if err := ha.Decode("login", token, &sessionType{}); err == nil {
				t.Fatalf("[%s] tampered-with token still decodes! (%d)", opt.name, i)
			}

			token[i]--
		}
	}
}

func TestDifferentSignKeyDoesntValidate(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		ha = New([]byte("some other sign key"), nil)
		if ha.Validate("login", token) {
			t.Fatalf("[%s] token validates with wrong sign key!", opt.name)
		}
	}
}

func TestDifferentContextDoesntValidate(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login1", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		if ha.Validate("login2", token) {
			t.Fatalf("[%s] token validates with wrong context!", opt.name)
		}
	}
}

func TestEncodesWithAnyHash(t *testing.T) {
	sha1Ha := New([]byte(signKey), &Options{
		Hash: sha1.New,
	})

	sha1Token, err := sha1Ha.Encode("login", newSess())
	if err != nil {
		t.Fatalf("Encode failed (%s)", err)
	}

	sha256Ha := New([]byte(signKey), &Options{
		Hash: sha256.New,
	})

	sha256Token, err := sha256Ha.Encode("login", newSess())
	if err != nil {
		t.Fatalf("Encode failed (%s)", err)
	}

	diff := (sha256.Size - sha1.Size) * 4 / 3

	if len(sha256Token)-len(sha1Token) != diff {
		t.Fatalf(
			"sha256 token should be %d bytes longer than sha1, instead %d",
			diff,
			len(sha256Token)-len(sha1Token),
		)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		start := newSess()

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode("login", start)
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		end := new(sessionType)
		if err := ha.Decode("login", token, end); err != nil {
			t.Fatalf("[%s] Encode-produced token doesn't Decode! (%s)", opt.name, err)
		}

		if !equal(start, end) {
			t.Fatalf(
				"[%s] Encode/Decode round trip messed up values (start: %+v, end: %+v)",
				opt.name,
				start,
				end,
			)
		}
	}
}

func TestProducesURLSafeTokens(t *testing.T) {
	safe := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$-_.+!*'()")

	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		start := newSess()

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode("login", start)
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		for _, b := range token {
			if !bytes.Contains(safe, []byte{b}) {
				t.Fatalf(
					"[%s] Encode produced unsafe byte %d",
					opt.name,
					b,
				)
			}
		}
	}
}

func TestSetsCookie(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		sess := newSess()

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode("login", sess)
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		w := httptest.NewRecorder()
		if err := ha.SetCookie("login", w, sess); err != nil {
			t.Fatalf("[%s] SetCookie failed (%s)", opt.name, err)
		}

		cval := cookieVal(w.HeaderMap.Get("Set-Cookie"))
		if !bytes.Equal(cval, token) {
			t.Fatalf(
				"[%s] mismatched cookie value and token '%s' vs '%s'",
				opt.name,
				string(cval),
				string(token),
			)
		}
	}
}

func TestClearsCookie(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		w := httptest.NewRecorder()
		ha.ClearCookie(w)

		cval := cookieVal(w.HeaderMap.Get("Set-Cookie"))
		if cval == nil || !bytes.Equal(cval, []byte{}) {
			t.Fatalf(
				"[%s] cookie value not being cleared: '%s'",
				opt.name,
				string(cval),
			)
		}
	}
}

func TestAuthenticates(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		start := newSess()

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode("login", start)
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		req, err := http.NewRequest("GET", "http://localhost/", nil)
		if err != nil {
			t.Fatalf("[%s] NewRequest failed (%s)", opt.name, err)
		}
		req.Header.Add("Cookie", ha.cookieName+"="+string(token))

		session := new(sessionType)
		err = ha.Authenticate("login", req, session)
		if err != nil {
			t.Fatalf("[%s] Authenticate failed (%s)", opt.name, err)
		}

		if !equal(start, session) {
			t.Fatalf(
				"[%s] Encode/Authenticate round trip messed up values (start: %+v, end: %+v)",
				opt.name,
				start,
				session,
			)
		}
	}
}

func TestTamperingPreventsAuth(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.opts)

		token, err := ha.Encode("login", newSess())
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		req, err := http.NewRequest("GET", "http://localhost/", nil)
		if err != nil {
			t.Fatalf("[%s] NewRequest failed (%s)", opt.name, err)
		}

		for i := 0; i < len(token)-4; i++ {
			token[i]++
			req.Header.Add("Cookie", ha.cookieName+"="+string(token))

			if err := ha.Authenticate("login", req, &sessionType{}); err == nil {
				t.Fatalf("[%s] tampered-with token still auths! (%d)", opt.name, i)
			}

			token[i]--
			req.Header.Del("Set-Cookie")
		}
	}
}

func TestSetsDefaultCookieName(t *testing.T) {
	ha := New([]byte(signKey), nil)

	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	s := strings.Split(cookies[0], "=")
	if s[0] != defaultCookieName {
		t.Fatalf(
			"SetCookie set the wrong cookie name! ('%s' instead of '%s')",
			s[0],
			defaultCookieName,
		)
	}
}

func TestSetsCustomCookieName(t *testing.T) {
	ha := New([]byte(signKey), &Options{CookieName: "othername"})
	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	s := strings.Split(cookies[0], "=")
	if s[0] != "othername" {
		t.Fatalf(
			"SetCookie set the wrong cookie name! ('%s' instead of '%s')",
			s[0],
			"othername",
		)
	}
}

func TestNoDefaultCookiePath(t *testing.T) {
	ha := New([]byte(signKey), nil)

	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	path := getCookieAttr(cookies[0], "path")
	if path != "" {
		t.Fatalf("SetCookie set a path without being provided one? ('%s')", path)
	}
}

func TestSetsCustomCookiePath(t *testing.T) {
	customPath := "/custom/path"
	ha := New([]byte(signKey), &Options{CookiePath: customPath})

	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	path := getCookieAttr(cookies[0], "path")
	if path == "" {
		t.Fatalf("SetCookie didn't set a path? ('%s')", cookies[0])
	}
	if path != customPath {
		t.Fatalf(
			"SetCookie set the wrong path (expected '%s', got '%s')",
			customPath,
			path,
		)
	}
}

func TestNoDefaultCookieDomain(t *testing.T) {
	ha := New([]byte(signKey), nil)
	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	domain := getCookieAttr(cookies[0], "domain")
	if domain != "" {
		t.Fatalf("default HashAuth options created a cookie domain? '%s'", domain)
	}
}

func TestCustomCookieDomain(t *testing.T) {
	customDomain := "custom.doma.in"
	ha := New([]byte(signKey), &Options{CookieDomain: customDomain})
	w := httptest.NewRecorder()
	ha.SetCookie("login", w, newSess())

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? %v", cookies)
	}

	domain := getCookieAttr(cookies[0], "domain")
	if domain != customDomain {
		t.Fatalf(
			"HashAuth with domain option created wrong cookie domain (expected '%s', got '%s'",
			customDomain,
			domain,
		)
	}
}

func TestCookieSecureBool(t *testing.T) {
	for _, opt := range []*Options{
		nil,
		&Options{CookieSecure: false},
		&Options{CookieSecure: true},
	} {
		ha := New([]byte(signKey), opt)
		w := httptest.NewRecorder()
		ha.SetCookie("login", w, newSess())

		cookies := (map[string][]string)(w.Header())["Set-Cookie"]
		if len(cookies) != 1 {
			t.Fatalf("SetCookie set more than one cookie? %v", cookies)
		}

		cs := false
		if opt != nil {
			cs = opt.CookieSecure
		}
		b := getCookieBoolAttr(cookies[0], "secure")
		if b != cs {
			t.Fatalf("SetCookie set the wrong 'secure' attribute (expected %v, got %v)", cs, b)
		}
	}
}

func TestCookieHTTPOnlyBool(t *testing.T) {
	for _, opt := range []*Options{
		nil,
		&Options{CookieHTTPOnly: false},
		&Options{CookieHTTPOnly: true},
	} {
		ha := New([]byte(signKey), opt)
		w := httptest.NewRecorder()
		ha.SetCookie("login", w, newSess())

		cookies := (map[string][]string)(w.Header())["Set-Cookie"]
		if len(cookies) != 1 {
			t.Fatalf("SetCookie set more than one cookie? %v", cookies)
		}

		ch := false
		if opt != nil {
			ch = opt.CookieHTTPOnly
		}
		b := getCookieBoolAttr(cookies[0], "httponly")
		if b != ch {
			t.Fatalf("SetCookie set the wrong 'httponly' attribute (expected %v, got %v)", ch, b)
		}
	}
}

func TestCookieExpires(t *testing.T) {
	ha := New([]byte(signKey), nil)
	w := httptest.NewRecorder()
	sess := (*expiringSession)(newSess())
	ha.SetCookie("login", w, sess)

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? '%s' %d", w.Header().Get("Set-Cookie"), len(cookies))
	}

	expireString := getCookieAttr(cookies[0], "expires")
	expected := strings.Replace(sess.Expiration.Format(time.RFC1123), "UTC", "GMT", -1)
	if expireString != expected {
		t.Fatalf(
			"SetCookie set the wrong expires (expected '%s', got '%s')",
			expected,
			expireString,
		)
	}
}

func TestCookieMaxAge(t *testing.T) {
	ha := New([]byte(signKey), nil)
	w := httptest.NewRecorder()
	sess := (*maxAgeSession)(newSess())
	ha.SetCookie("login", w, sess)

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? '%s' %d", w.Header().Get("Set-Cookie"), len(cookies))
	}

	maString := getCookieAttr(cookies[0], "max-age")
	expected := strconv.Itoa(int(sess.Expiration.Sub(time.Now().UTC()) / time.Second))
	if maString != expected {
		t.Fatalf(
			"SetCookie set the wrong max-age (expected '%s', got '%s')",
			expected,
			maString,
		)
	}
}

func TestExpiresTakesPrecedence(t *testing.T) {
	ha := New([]byte(signKey), nil)
	w := httptest.NewRecorder()
	sess := (*flexibleSession)(newSess())
	ha.SetCookie("login", w, sess)

	cookies := (map[string][]string)(w.Header())["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set more than one cookie? '%s' %d", w.Header().Get("Set-Cookie"), len(cookies))
	}

	expireString := getCookieAttr(cookies[0], "expires")
	expected := strings.Replace(sess.Expiration.Format(time.RFC1123), "UTC", "GMT", -1)
	if expireString != expected {
		t.Fatalf(
			"SetCookie set the wrong expires (expected '%s', got '%s')",
			expected,
			expireString,
		)
	}

	maString := getCookieAttr(cookies[0], "max-age")
	if maString != "" {
		t.Fatalf("Expirer should have taken precedence over MaxAger")
	}
}

type sessionType struct {
	UserID     int64
	Expiration time.Time
}

type expiringSession sessionType

func (es *expiringSession) Expires() time.Time {
	return es.Expiration
}

type maxAgeSession sessionType

func (ms *maxAgeSession) MaxAge() time.Duration {
	return ms.Expiration.Sub(time.Now().UTC())
}

type flexibleSession sessionType

func (fs *flexibleSession) Expires() time.Time {
	return (*expiringSession)(fs).Expires()
}

func (fs *flexibleSession) MaxAge() time.Duration {
	return (*maxAgeSession)(fs).MaxAge()
}

func equal(a, b *sessionType) bool {
	if a.UserID != b.UserID {
		return false
	}

	return a.Expiration == b.Expiration
}

type optionsList []struct {
	name string
	opts *Options
}

func newSess() *sessionType {
	return &sessionType{
		UserID:     56,
		Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
}

func cookieVal(fullHeader string) []byte {
	s := bytes.SplitN([]byte(fullHeader), []byte{'='}, 2)
	if len(s) < 2 {
		return nil
	}
	s = bytes.SplitN(s[1], []byte{';'}, 2)

	return s[0]
}

func getCookieAttr(cookieString, attr string) string {
	s := strings.Split(cookieString, ";")
	for _, item := range s {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(strings.ToLower(item), strings.ToLower(attr)+"=") {
			return item[len(attr)+1:]
		}
	}
	return ""
}

func getCookieBoolAttr(cookieString, attr string) bool {
	s := strings.Split(cookieString, ";")
	for _, item := range s {
		item = strings.TrimSpace(item)
		if strings.ToLower(item) == strings.ToLower(attr) {
			return true
		}
	}
	return false
}
