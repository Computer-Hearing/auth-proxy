package users

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/domain"
	"auth-proxy/pkg/password"
	"fmt"
)

// FromConfig превращает пользователей конфига в доменных: хеширует пароль
// и заранее считает заголовок Basic для jwt2basic-маршрутов (после
// хеширования открытый пароль уже недоступен).
// Поля зовутся по-разному: login -> username, full_name -> first_name.
func FromConfig(access config.AccessConfig) ([]domain.User, error) {
	users := make([]domain.User, 0, len(access.Users))
	for _, u := range access.Users {
		hashed, err := password.Hash(u.Password, access.BcryptCost)
		if err != nil {
			return nil, fmt.Errorf("user %q: hash password: %w", u.Login, err)
		}
		users = append(users, domain.User{
			ID:             u.ID,
			Username:       u.Login,
			Email:          u.Email,
			FirstName:      u.FullName,
			HashedPassword: hashed,
			Role:           u.Role,
			BasicAuth:      password.BasicAuthHeader(u.Login, u.Password),
		})
	}
	return users, nil
}
