package password

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Hash - хеширует пароль с автоматической солью
func Hash(password string, cost int) (string, error) {
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

// Check - проверяет пароль против хеша
func Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// BasicAuthHeader - формирует значение заголовка Authorization: Basic base64(login:password)
func BasicAuthHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+password))
}
