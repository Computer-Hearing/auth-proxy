package authentik

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

// Заголовки, которые проставляет Authentik (forward_auth + Caddy).
const (
	HeaderUsername = "X-authentik-username"
	HeaderEmail    = "X-authentik-email"
	HeaderGroups   = "X-authentik-groups"
)

// Identity - доверенные данные пользователя из заголовков Authentik.
type Identity struct {
	Username string
	Email    string
	Groups   []string
	Secret   string
}

type ctxKey int

const identityKey ctxKey = 0

// Middleware читает заголовки Authentik в context.
// Секрет пока только читается; проверка не выполняется (TODO).
func Middleware(secretHeader string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := Identity{
				Username: strings.TrimSpace(r.Header.Get(HeaderUsername)),
				Email:    strings.TrimSpace(r.Header.Get(HeaderEmail)),
				Groups:   ParseGroups(r.Header.Get(HeaderGroups)),
				Secret:   r.Header.Get(secretHeader),
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
		})
	}
}

// FromContext достаёт Identity (пустая, если middleware не было).
func FromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey).(Identity)
	return id
}

// ParseGroups разбирает X-authentik-groups: "foo|bar|baz".
func ParseGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "|")
	groups := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			groups = append(groups, p)
		}
	}
	return groups
}

// UserRank - индекс самой высокой роли пользователя в roles (0 - высшая).
// -1, если ни одна группа не известна.
func UserRank(roles, groups []string) int {
	rank := -1
	for _, group := range groups {
		idx := slices.Index(roles, group)
		if idx < 0 {
			continue
		}
		if rank < 0 || idx < rank {
			rank = idx
		}
	}
	return rank
}

// Allows - проходит ли пользователь по required_groups с учётом «лесенки»:
// roles упорядочены по убыванию, и роль выше покрывает требования ниже.
func Allows(roles, groups, required []string) bool {
	userRank := UserRank(roles, groups)
	if userRank < 0 {
		return false
	}

	requiredRank := -1
	for _, group := range required {
		if idx := slices.Index(roles, group); idx >= 0 && idx > requiredRank {
			requiredRank = idx
		}
	}
	if requiredRank < 0 {
		return false
	}
	return userRank <= requiredRank
}

// IsTop - есть ли у пользователя самая высокая роль (roles[0]).
func IsTop(roles, groups []string) bool {
	return UserRank(roles, groups) == 0
}

// WarnUnknown логирует группы, которых нет в roles (они игнорируются).
func WarnUnknown(logger *slog.Logger, username string, roles, groups []string) {
	if logger == nil {
		return
	}
	for _, group := range groups {
		if !slices.Contains(roles, group) {
			logger.Warn("authentik: unknown group ignored",
				slog.String("group", group),
				slog.String("username", username),
			)
		}
	}
}
