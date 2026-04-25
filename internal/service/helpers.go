package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	apperrors "GoAuth/internal/errors"
)

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomOTP6() (string, error) {
	digits := make([]byte, 6)
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		digits[i] = byte('0' + n.Int64())
	}
	return string(digits), nil
}

func safeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func mapValidationErr(err error) *apperrors.AppError {
	if err == nil {
		return nil
	}
	return apperrors.Wrap(
		apperrors.ErrValidationFailed.Code,
		apperrors.ErrValidationFailed.Message,
		apperrors.ErrValidationFailed.HTTPStatus,
		err,
	)
}

func nowUTC() time.Time {
	return time.Now().UTC()
}
