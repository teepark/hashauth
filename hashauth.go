package hashauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"hash"
)

const padChar = '.'

// ErrInvalid is returned from Decode when a token proves to be invalid.
var ErrInvalid = errors.New("token validation failed")

var defaultHasher = sha1.New

// New creates a new HashAuth En/Decoder.
// key should be a carefully guarded secret, with it anyone could forge a token.
// opts can be nil, in which case a sha1 hasher will be used.
func New(key []byte, hasher func() hash.Hash) *HashAuth {
	if hasher == nil {
		hasher = defaultHasher
	}

	return &HashAuth{
		key:    key,
		hasher: hasher,
	}
}

// An Encoder and Decoder of tokens.
type HashAuth struct {
	key    []byte
	hasher func() hash.Hash
}

// Encode produces a signed token with session data.
func (ha *HashAuth) Encode(session interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := gob.NewEncoder(buf).Encode(session)
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
	hash_size := ha.hasher().Size()

	length := len(token)
	if length < hash_size+1 {
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
	return gob.NewDecoder(buf).Decode(container)
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
