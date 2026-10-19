package domain

import "auth-proxy/pkg/password"

type User struct {
	ID             int64  `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	HashedPassword string `json:"-"`
	Role           string `json:"role"`
	LastActivity   string `json:"last_activity"`
	// BasicAuth - готовый заголовок Authorization: Basic (base64(login:password))
	// для jwt2basic-маршрутов. Заполняется при загрузке пользователей, в JSON не попадает.
	BasicAuth string `json:"-"`
}

func (u *User) CheckPassword(pass string) bool {
	return password.Check(pass, u.HashedPassword)
}
