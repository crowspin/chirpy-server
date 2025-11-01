package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}
func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userID.String(),
	})
	return token.SignedString([]byte(tokenSecret))
}
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	rv, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	if subj, err := rv.Claims.GetSubject(); err != nil {
		return uuid.UUID{}, err
	} else {
		return uuid.Parse(subj)
	}
}
func GetBearerToken(headers http.Header) (string, error) {
	val := headers.Get("Authorization")
	re := regexp.MustCompile(`(?m)Bearer (.*)$`)
	match := re.FindStringSubmatch(val)
	if match == nil {
		return "", errors.New("no bearer token available")
	}
	return match[1], nil
}
func MakeRefeshToken() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
	//Lesson instructed that this should have a secondary error return, but if you read the docs, rand.Read never fails and only returns an error as a formality; it's impossible for this function to produce an error.
}
