package hashauth

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"
)

const signKey = "asdokjwp9RIKMOEW9Vrj39f8j43;oiESJG"

var opts optionsList = optionsList{
	{"nil", nil},
	{"md5", md5.New},
	{"sha1", sha1.New},
	{"sha256", sha256.New},
	{"sha512", sha512.New},
}

func TestTokenValidates(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.hasher)

		token, err := ha.Encode(&sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		if !ha.Validate(token) {
			t.Fatalf("[%s] Encode-produced token doesn't Validate!", opt.name)
		}
	}
}

func TestTamperedTokenDoesntValidate(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.hasher)

		token, err := ha.Encode(&sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		// base64 has some slop: changing something in the last 4 bytes
		// can sometimes still yield an equivalent decoded plaintext
		for i := 0; i < len(token)-4; i++ {
			token[i]++

			if ha.Validate(token) {
				t.Fatalf("[%s] tampered-with token still validates! (%d)", opt.name, i)
			}

			token[i]--
		}
	}
}

func testTamperedTokenDoesntDecode(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.hasher)

		token, err := ha.Encode(&sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		for i := 0; i < len(token); i++ {
			token[i]++

			if err := ha.Decode(token, &sessionType{}); err == nil {
				t.Fatalf("[%s] tampered-with token still decodes! (%d)", opt.name, i)
			}

			token[i]--
		}
	}
}

func TestDifferentSignKeyDoesntValidate(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.hasher)

		token, err := ha.Encode(&sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		ha = New([]byte("some other sign key"), nil)
		if ha.Validate(token) {
			t.Fatalf("[%s] token validates with wrong sign key!", opt.name)
		}
	}
}

func TestEncodesWithAnyHash(t *testing.T) {
	sha1_ha := New([]byte(signKey), sha1.New)

	sha1_token, err := sha1_ha.Encode(&sessionType{
		UserID:     56,
		Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Encode failed (%s)", err)
	}

	sha256_ha := New([]byte(signKey), sha256.New)

	sha256_token, err := sha256_ha.Encode(&sessionType{
		UserID:     56,
		Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Encode failed (%s)", err)
	}

	diff := (sha256.Size - sha1.Size) * 4 / 3

	if len(sha256_token)-len(sha1_token) != diff {
		t.Fatalf(
			"sha256 token should be %d bytes longer than sha1, instead %d",
			diff,
			len(sha256_token)-len(sha1_token),
		)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, opt := range opts {
		ha := New([]byte(signKey), opt.hasher)

		start := &sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		}

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode(start)
		if err != nil {
			t.Fatalf("[%s] Encode failed (%s)", opt.name, err)
		}

		end := new(sessionType)
		if err := ha.Decode(token, end); err != nil {
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
		ha := New([]byte(signKey), opt.hasher)

		start := &sessionType{
			UserID:     56,
			Expiration: time.Now().UTC().Add(30 * 24 * time.Hour),
		}

		var (
			token []byte
			err   error
		)

		token, err = ha.Encode(start)
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

type sessionType struct {
	UserID     int64
	Expiration time.Time
}

func equal(a, b *sessionType) bool {
	if a.UserID != b.UserID {
		return false
	}

	return a.Expiration == b.Expiration
}

type optionsList []struct {
	name   string
	hasher func() hash.Hash
}
