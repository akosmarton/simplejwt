package simplejwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ParseToken parses a JWT token and validates (only) the signature
func ParseToken(token string, key []byte) (map[string]interface{}, bool, error) {
	t := strings.SplitN(token, ".", 3)
	if len(t) != 3 {
		return nil, false, errors.New("Invalid token format")
	}

	jh, err := base64.URLEncoding.DecodeString(t[0])
	if err != nil {
		return nil, false, err
	}

	jf, err := base64.URLEncoding.DecodeString(t[1])
	if err != nil {
		return nil, false, err
	}

	s, err := base64.URLEncoding.DecodeString(t[2])
	if err != nil {
		return nil, false, err
	}

	h := make(map[string]string)
	err = json.Unmarshal(jh, &h)
	if err != nil {
		return nil, false, err
	}
	if h["typ"] != "JWT" {
		return nil, false, errors.New("Unsupported type: " + h["typ"])
	}
	if h["alg"] != "HS256" {
		return nil, false, errors.New("Unsupported hash algorithm: " + h["alg"])
	}

	f := make(map[string]interface{})
	err = json.Unmarshal(jf, &f)
	if err != nil {
		return nil, false, err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(t[0]))
	mac.Write([]byte("."))
	mac.Write([]byte(t[1]))
	c := mac.Sum(nil)

	return f, hmac.Equal(s, c), nil
}

// NewToken generates a new JWT token. You should fill the claim fields.
func NewToken(fields map[string]interface{}, key []byte) (string, error) {
	t := make([]string, 3)

	jh, err := json.Marshal(&map[string]string{"typ": "JWT", "alg": "HS256"})
	if err != nil {
		return "", err
	}
	t[0] = base64.URLEncoding.EncodeToString(jh)

	jf, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	t[1] = base64.URLEncoding.EncodeToString(jf)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(t[0]))
	mac.Write([]byte("."))
	mac.Write([]byte(t[1]))
	t[2] = base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return strings.Join(t, "."), nil
}

// VerifyFields verifies all fields
func VerifyFields(fields map[string]interface{}) bool {
	now := time.Now().UTC().Unix()

	if exp, ok := fields["exp"]; ok {
		if VerifyExp(exp, now) == false {
			return false
		}
	}

	if nbf, ok := fields["nbf"]; ok {
		if VerifyNbf(nbf, now) == false {
			return false
		}
	}

	if iat, ok := fields["iat"]; ok {
		if VerifyIat(iat, now) == false {
			return false
		}
	}

	return true
}

// VerifyExp verifies exp field
func VerifyExp(exp interface{}, now int64) bool {
	switch v := exp.(type) {
	case float64:
		return verifyExp(int64(v), now)
	case json.Number:
		i, _ := v.Int64()
		return verifyExp(i, now)
	}

	return false
}

// VerifyNbf verifies nbf field
func VerifyNbf(nbf interface{}, now int64) bool {
	switch v := nbf.(type) {
	case float64:
		return verifyNbf(int64(v), now)
	case json.Number:
		i, _ := v.Int64()
		return verifyNbf(i, now)
	}

	return false
}

// VerifyIat verifies iat field
func VerifyIat(iat interface{}, now int64) bool {
	switch v := iat.(type) {
	case float64:
		return verifyIat(int64(v), now)
	case json.Number:
		i, _ := v.Int64()
		return verifyIat(i, now)
	}

	return false
}

func verifyExp(exp int64, now int64) bool {
	return now <= exp
}

func verifyNbf(nbf int64, now int64) bool {
	return now >= nbf
}

func verifyIat(iat int64, now int64) bool {
	return now >= iat
}
