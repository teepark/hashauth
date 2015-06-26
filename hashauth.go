/*
Package hashauth provides a means of creating a cookie- and url-friendly token
containing arbitrary encoded information, with an embedded authentication code
that ensures that it was created by you (not forged) and is in its original
form  (not tampered with).

Primary use-cases are login sessions, password reset tokens, and the like. Any
situation where you need to provide to the user a token they can present back
to you which contains a small amount of data and authentication guarantees.

The package provides methods for Encoding, Validating, and Decoding tokens,
and also a higher-level API for interacting with HTTP request and response
cookies for sessions.

Login session example:

	var Signer = hashauth.New([]byte("secret key"), nil)
	const loginCtx = "login"

	type LoginSession struct {
		UserID     int
		Expiration time.Time
	}

	// implementing this method causes hashauth to set the Expires cookie attr
	func (sess *LoginSession) Expires() time.Time {
		return sess.Expiration
	}

	func AuthRequired(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := new(LoginSession)
			err := Signer.Authenticate(loginCtx, r, sess)
			if err != nil {
				http.Error(w, "Login Required", http.StatusForbidden)
			} else if time.Now().UTC().Before(sess.Expiration) {
				// check the expiration, cookie attributes can be tampered with
				http.Error(w, "Login Expired", http.StatusForbidden)
			} else {
				h.ServeHTTP(w, r)
			}
		})
	}

	func LogUserIn(w http.ResponseWriter, uid int) error {
		return Signer.SetCookie(loginCtx, w, &LoginSession{
			UserID:     uid,
			Expiration: time.Now().UTC().Add(7*24*time.Hour),
		})
	}

	func LogUserOut(w http.ResponseWriter) {
		Signer.ClearCookie(w)
	}
*/
package hashauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ugorji/go/codec"
)

const padChar = '.'

// ErrInvalid is returned when an authentication check fails
var ErrInvalid = errors.New("token validation failed")

var (
	defaultHasher     = sha256.New
	defaultCookieName = "_ha"
	mh                codec.MsgpackHandle
)

// Options is a simple container for various HashAuth options.
type Options struct {
	Hash           func() hash.Hash
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSecure   bool
	CookieHTTPOnly bool
}

// HashAuth is an Encoder and Decoder of tokens.
type HashAuth struct {
	key            []byte
	hasher         func() hash.Hash
	cookieName     string
	cookiePath     string
	cookieDomain   string
	cookieSecure   bool
	cookieHTTPOnly bool
}

// Expirer can be implemented by session data types, in which case their
// expiration time will be set as the cookie expiration time in
// HashAuth.SetCookie.
type Expirer interface {
	Expires() time.Time
}

// MaxAger can be implemented by session data types, in which case the
// HashAuth.SetCookie method will set a max-age attribute (unless it
// also implements Expirer, which takes precedence).
type MaxAger interface {
	MaxAge() time.Duration
}

// New creates a new HashAuth En/Decoder.
// key should be a carefully guarded secret, with it anyone could forge a token.
// opts can be nil, in which case a sha256 hasher, a default cookie name, and
// no cookie attributes will be used.
func New(key []byte, opts *Options) *HashAuth {
	if opts == nil {
		opts = &Options{}
	}

	hasher := opts.Hash
	if hasher == nil {
		hasher = defaultHasher
	}

	cname := opts.CookieName
	if cname == "" {
		cname = defaultCookieName
	}

	return &HashAuth{
		key:            key,
		hasher:         hasher,
		cookieName:     cname,
		cookiePath:     opts.CookiePath,
		cookieDomain:   opts.CookieDomain,
		cookieSecure:   opts.CookieSecure,
		cookieHTTPOnly: opts.CookieHTTPOnly,
	}
}

// Encode produces a signed token with session data.
func (ha *HashAuth) Encode(session interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := encodeKeyless(buf, session)
	if err != nil {
		return nil, err
	}

	hasher := hmac.New(ha.hasher, ha.key)
	hasher.Write(buf.Bytes())
	mac := hasher.Sum(nil)

	_, err = buf.Write(mac)
	if err != nil {
		return nil, err
	}

	return b64encode(buf.Bytes()), nil
}

// Validate tests a token's signature and returns whether it it valid.
func (ha *HashAuth) Validate(token []byte) bool {
	token, err := b64decode(token)
	if err != nil {
		return false
	}
	return ha.validate(token)
}

func (ha *HashAuth) validate(token []byte) bool {
	hashSize := ha.hasher().Size()

	length := len(token)
	if length < hashSize+1 {
		return false
	}

	hasher := hmac.New(ha.hasher, ha.key)
	hasher.Write(token[:length-hasher.Size()])

	mac1 := token[length-hasher.Size():]
	mac2 := hasher.Sum(nil)

	if !hmac.Equal(mac1, mac2) {
		return false
	}

	return true
}

// Decode checks a token's validity and extracts the data encoded in it.
// May return ErrInvalid if the validity check fails.
func (ha *HashAuth) Decode(token []byte, container interface{}) error {
	token, err := b64decode(token)
	if err != nil {
		return err
	}

	if !ha.validate(token) {
		return ErrInvalid
	}

	buf := bytes.NewBuffer(token)
	return decodeKeyless(container, buf)
}

// Authenticate finds and decodes the auth token from a request, populating
// the container with the session data.
// It will return nil on success, or:
//  - http.ErrNoCookie if there is no auth header at all
//  - a decoding error if it is malformed
//  - ErrInvalid if there is a properly formatted token that is invalid
func (ha *HashAuth) Authenticate(r *http.Request, container interface{}) error {
	cookie, err := r.Cookie(ha.cookieName)
	if err != nil {
		return err
	}
	return ha.Decode([]byte(cookie.Value), container)
}

// SetCookie adds an encoded token as a cookie on an HTTP response.
// If the provided session data object implements the Expirer or MaxAger
// interfaces, then the corresponding cookie attribute will also be set.
// Other cookie attributes will be set according to the *Options with
// which the HashAuth was created.
func (ha *HashAuth) SetCookie(w http.ResponseWriter, session interface{}) error {
	token, err := ha.Encode(session)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     ha.cookieName,
		Value:    string(token),
		Path:     ha.cookiePath,
		Domain:   ha.cookieDomain,
		Secure:   ha.cookieSecure,
		HttpOnly: ha.cookieHTTPOnly,
	}
	augmentCookie(cookie, session)
	w.Header().Add("Set-Cookie", fmtCookie(cookie))
	return nil
}

// ClearCookie adds a Set-Cookie header to a response that will remove
// the auth cookie.
func (ha *HashAuth) ClearCookie(w http.ResponseWriter) {
	w.Header().Add("Set-Cookie", fmtCookie(&http.Cookie{
		Name:     ha.cookieName,
		Value:    "",
		Path:     ha.cookiePath,
		Domain:   ha.cookieDomain,
		Secure:   ha.cookieSecure,
		HttpOnly: ha.cookieHTTPOnly,
		MaxAge:   -1,
	}))
}

func augmentCookie(cookie *http.Cookie, session interface{}) {
	var (
		expire time.Time
		maxage time.Duration
	)

	if sess, ok := session.(Expirer); ok {
		expire = sess.Expires().UTC()
	}
	if !expire.IsZero() {
		//TODO: find out exactly: for which browsers is this necessary?
		s := expire.Format(time.RFC1123)
		if strings.HasSuffix(s, "UTC") {
			s = s[:len(s)-3] + "GMT"
		}
		cookie.RawExpires = s
		return
	}

	if sess, ok := session.(MaxAger); ok {
		maxage = sess.MaxAge()
	}
	if maxage != 0 {
		cookie.MaxAge = int(maxage / time.Second)
	}
}

func fmtCookie(cookie *http.Cookie) string {
	cookie.Expires = time.Time{}
	if len(cookie.RawExpires) > 0 {
		return fmt.Sprintf("%s; Expires=%s", cookie.String(), cookie.RawExpires)
	}
	return cookie.String()
}

func b64encode(plain []byte) []byte {
	enc := make([]byte, base64.URLEncoding.EncodedLen(len(plain)))
	base64.URLEncoding.Encode(enc, plain)
	return bytes.Replace(enc, []byte{'='}, []byte{padChar}, -1)
}

func b64decode(enc []byte) ([]byte, error) {
	plain := make([]byte, base64.URLEncoding.DecodedLen(len(enc)))

	enc = bytes.Replace(enc, []byte{padChar}, []byte{'='}, -1)

	n, err := base64.URLEncoding.Decode(plain, enc)
	if err != nil {
		return nil, err
	}

	return plain[:n], nil
}

func deref(val reflect.Value) reflect.Value {
	kind := val.Kind()
	for kind == reflect.Ptr || kind == reflect.Interface {
		val = val.Elem()
		kind = val.Kind()
	}
	return val
}

func getKeys(t reflect.Type) []string {
	if t.Kind() != reflect.Struct {
		return nil
	}

	num := t.NumField()
	keys := make([]string, num)
	j := 0
	for i := 0; i < num; i++ {
		key := t.Field(i).Name
		if key[0:1] != strings.ToUpper(key[0:1]) {
			continue
		}
		keys[j] = key
		j++
	}
	keys = keys[:j]

	sort.Strings(keys)
	return keys
}

func encodeKeyless(w io.Writer, obj interface{}) error {
	enc := codec.NewEncoder(w, &mh)
	val := deref(reflect.ValueOf(obj))

	keys := getKeys(val.Type())
	if keys == nil {
		return enc.Encode(obj)
	}

	for _, key := range keys {
		err := enc.Encode(val.FieldByName(key).Interface())
		if err != nil {
			return err
		}
	}

	return nil
}

func decodeKeyless(dest interface{}, r io.Reader) error {
	dec := codec.NewDecoder(r, &mh)
	val := deref(reflect.ValueOf(dest))

	keys := getKeys(val.Type())
	if keys == nil {
		return dec.Decode(dest)
	}

	for _, key := range keys {
		dest = val.FieldByName(key).Addr().Interface()
		err := dec.Decode(&dest)
		if err != nil {
			return err
		}
	}

	return nil
}
