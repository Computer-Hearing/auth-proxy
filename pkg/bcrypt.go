package pkg

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword - хеширует пароль с автоматической солью
func HashPassword(password string, cost int) (string, error) {
	hashCost := cost
	if hashCost < bcrypt.MinCost || hashCost > bcrypt.MaxCost {
		hashCost = bcrypt.DefaultCost
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", fmt.Errorf("hashing password failed: %v", err)
	}
	return string(hashed), nil
}

// CheckPassword - проверяет пароль против хеша
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// BasicAuthHeader - формирует значение заголовка Authorization: Basic base64(login:password)
func BasicAuthHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+password))
}
