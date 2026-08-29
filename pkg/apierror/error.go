package apierror

import (
	"auth-proxy/pkg"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Всякие ошибки
var (
	ErrPathNotFound error = APIError{
		StatusCode: http.StatusNotFound,
		Message:    "path not found in config",
	}
	ErrIPIsInvalid error = APIError{
		StatusCode: http.StatusBadRequest,
		Message:    "ip is invalid",
	}
	ErrBlacklistedIP error = APIError{
		StatusCode: http.StatusForbidden,
		Message:    "ip is blacklisted",
	}
	// ErrUnauthorized - нет токена или он невалидной (клиент не вошёл)
	ErrUnauthorized error = APIError{
		StatusCode: http.StatusUnauthorized,
		Message:    "unauthorized",
	}
	// ErrForbidden - токен валиден, но роль недостаточна для маршрута
	ErrForbidden error = APIError{
		StatusCode: http.StatusForbidden,
		Message:    "forbidden: insufficient role",
	}
)

type APIError struct {
	StatusCode int               `json:"status_code"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details"`
}

func (e APIError) Error() string {
	details := e.stringDetails()
	if details == "" {
		return e.Message
	}
	return fmt.Sprintf("%s. %s", e.Message, details)
}

func (e APIError) stringDetails() string {
	if len(e.Details) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Details: ")
	i := 0
	for k, v := range e.Details {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		i++
	}
	return b.String()
}

func HandleAPIError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if errApi, ok := errors.AsType[APIError](err); ok {
		pkg.SendError(logger, w, &errApi, errApi.StatusCode)
		return
	}
	pkg.SendError(logger, w, err, http.StatusInternalServerError)
}
