package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func TokenHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

const (
	MinPasswordBytes   = 10
	MaxPasswordBytes   = 256
	PasswordIterations = 600000
)

func ValidatePassword(password string) error {
	if len(password) < MinPasswordBytes {
		return errors.New("password must be at least 10 characters")
	}
	if len(password) > MaxPasswordBytes {
		return errors.New("password must not exceed 256 bytes")
	}
	return nil
}

// PBKDF2-HMAC-SHA256 is implemented locally so ZentContainer has no runtime Go crypto dependency.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2([]byte(password), salt, PasswordIterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", PasswordIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}
func VerifyPassword(encoded, password string) bool {
	if len(password) > MaxPasswordBytes {
		return false
	}
	p := strings.Split(encoded, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter <= 0 || iter > 10000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[2])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p[3])
	if err != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func PasswordNeedsRehash(encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	return err == nil && iter > 0 && iter < PasswordIterations
}

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	if iter <= 0 || keyLen <= 0 {
		return nil
	}
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	mac := hmac.New(sha256.New, password)
	for i := 1; i <= blocks; i++ {
		mac.Reset()
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 1; j < iter; j++ {
			mac.Reset()
			_, _ = mac.Write(u)
			u = mac.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
