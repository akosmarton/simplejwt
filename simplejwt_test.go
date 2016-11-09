package simplejwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const SECRET = "secret"
const INVALIDSECRET = "invalidsecret"

func TestParseNewToken(t *testing.T) {
	f := make(map[string]interface{})

	f["iat"] = time.Now().UTC().Unix()
	f["exp"] = time.Now().UTC().Add(time.Hour).Unix()
	f["nbf"] = time.Now().UTC().Add(-time.Hour).Unix()

	tok, err := NewToken(f, []byte(SECRET))
	if err != nil {
		t.Fail()
	}

	f2, ok, err := ParseToken(tok, []byte(SECRET))
	if err != nil {
		t.Fail()
	}
	if ok != true {
		t.Fail()
	}

	if f["sub"] != f2["sub"] {
		t.Fail()
	}

	if VerifyFields(f2) != true {
		t.Fail()
	}
}

func TestParseNewTokenExpired(t *testing.T) {
	f := map[string]interface{}{"sub": "subject", "exp": time.Now().UTC().Add(-time.Hour).Unix()}

	tok, err := NewToken(f, []byte(SECRET))
	if err != nil {
		t.Fail()
	}

	f2, ok, err := ParseToken(tok, []byte(SECRET))
	if err != nil {
		t.Fail()
	}
	if ok != true {
		t.Fail()
	}

	if VerifyExp(f2["exp"], time.Now().UTC().Unix()) != false {
		t.Fail()
	}
}

func TestParseNewTokenInvalid(t *testing.T) {
	p := map[string]interface{}{"sub": "subject"}

	tok, err := NewToken(p, []byte(INVALIDSECRET))
	if err != nil {
		t.Fail()
	}

	_, ok, err := ParseToken(tok, []byte(SECRET))
	if err != nil {
		t.Fail()
	}
	if ok != false {
		t.Fail()
	}
}

func TestParseInvalidTokenFormat(t *testing.T) {
	_, _, err := ParseToken("", []byte(SECRET))
	if err == nil {
		t.Fail()
	}
	if strings.Contains(err.Error(), "Invalid token format") == false {
		t.Fail()
	}

	_, _, err = ParseToken(base64.URLEncoding.EncodeToString([]byte("{}.{}")), []byte(SECRET))
	if err == nil {
		t.Fail()
	}
	if strings.Contains(err.Error(), "Invalid token format") == false {
		t.Fail()
	}
}

func TestParseUnsupportedType(t *testing.T) {
	bh := base64.URLEncoding.EncodeToString([]byte(`{"typ":"JwT","alg":"HS256"}`))
	bp := base64.URLEncoding.EncodeToString([]byte("{}"))
	bs := base64.URLEncoding.EncodeToString([]byte(""))

	_, _, err := ParseToken(bh+"."+bp+"."+bs, []byte(SECRET))
	if err == nil {
		t.Fail()
	}
	if strings.Contains(err.Error(), "Unsupported type") == false {
		t.Fail()
	}
}

func TestParseUnsupportedHashAlgo(t *testing.T) {
	bh := base64.URLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"RS256"}`))
	bp := base64.URLEncoding.EncodeToString([]byte("{}"))
	bs := base64.URLEncoding.EncodeToString([]byte(""))

	_, _, err := ParseToken(bh+"."+bp+"."+bs, []byte(SECRET))
	if err == nil {
		t.Fail()
	}
	if strings.Contains(err.Error(), "Unsupported hash algorithm") == false {
		t.Fail()
	}
}

func BenchmarkNewToken(b *testing.B) {
	f := make(map[string]interface{})

	f["iat"] = time.Now().UTC().Unix()
	f["exp"] = time.Now().UTC().Add(time.Hour).Unix()
	f["nbf"] = time.Now().UTC().Add(-time.Hour).Unix()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewToken(f, []byte(SECRET))
	}
}

func BenchmarkParseToken(b *testing.B) {
	f := make(map[string]interface{})

	f["iat"] = time.Now().UTC().Unix()
	f["exp"] = time.Now().UTC().Add(time.Hour).Unix()
	f["nbf"] = time.Now().UTC().Add(-time.Hour).Unix()

	t, _ := NewToken(f, []byte(SECRET))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseToken(t, []byte(SECRET))
	}
}
