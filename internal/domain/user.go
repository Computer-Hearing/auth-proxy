package domain

import (
	"auth-proxy/pkg"
	"auth-proxy/pkg/apierror"
	"fmt"
	"net/http"
	"net/mail"
)

type User struct {
	ID             int64  `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	HashedPassword string `json:"-"`
	Role           string `json:"role"`
	LastActivity   string `json:"last_activity"`
}

func (u *User) Validate() error {
	isValid := true
	var errorsMap = make(map[string]string)

	if len(u.FirstName) < pkg.MinFirstNameLen || len(u.FirstName) > pkg.MaxFirstNameLen {
		isValid = false
		errorsMap["first_name"] = fmt.Sprintf("firstname must be between %d and %d. Got %s",
			pkg.MinFirstNameLen, pkg.MaxFirstNameLen, u.FirstName)
	}

	if len(u.Username) < pkg.MinUsernameLen || len(u.Username) > pkg.MaxUsernameLen {
		isValid = false
		errorsMap["username"] = fmt.Sprintf("username must be between %d and %d. Got %s",
			pkg.MinUsernameLen, pkg.MaxUsernameLen, u.Username)
	}

	if len(u.HashedPassword) < pkg.MinHashedPasswordLen {
		isValid = false
		errorsMap["hashed_password"] = "hashed password is too short"
	}

	if _, err := mail.ParseAddress(u.Email); err != nil || len(u.Email) == 0 {
		isValid = false
		errorsMap["email"] = "email address is invalid"
	}

	if !isValid {
		return apierror.APIError{
			StatusCode: http.StatusBadRequest,
			Message:    "user validation failed",
			Details:    errorsMap,
		}
	}
	return nil
}

func (u *User) CheckPassword(password string) bool {
	return pkg.CheckPassword(password, u.HashedPassword)
}
