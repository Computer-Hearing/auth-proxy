package httpx

import (
	"net/url"
	"strings"
)

// SafeNext - защита от open redirect.
//
// next приходит из query-параметра (?next=...), по нему auth-сервис
// редиректит после логина/обновления токена. Если принять любой адрес,
// злоумышленник сделает ссылку ?next=https://evil.com и уведёт туда после входа.
//
// Разрешаем:
//   - внутренний относительный путь: начинается с "/", не с "//"
//     (protocol-relative), первый сегмент без ":" (http:, javascript: и т.п.);
//   - абсолютный http(s) URL без userinfo, если его host разрешён allowHost
//     (нужно, чтобы вернуть пользователя на тот домен, с которого он пришёл).
//
// Не подходит - возвращаем "/" (жёсткий fallback вместо ошибки),
// чтобы авторизованному пользователю не показать ошибку.
func SafeNext(next string, allowHost func(host string) bool) string {
	if strings.HasPrefix(next, "/") {
		return safePath(next)
	}

	u, err := url.Parse(next)
	if err != nil || allowHost == nil {
		return "/"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "/"
	}
	// user@host: браузер уходит на host, а глазу видно user - не пускаем
	if u.Host == "" || u.User != nil || !allowHost(u.Host) {
		return "/"
	}
	// отдаём то, что проверили, а не исходную строку
	return u.String()
}

// IsAbsolute - next с указанием схемы и хоста (результат SafeNext)
func IsAbsolute(next string) bool {
	return strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://")
}

func safePath(next string) string {
	if strings.HasPrefix(next, "//") {
		return "/"
	}

	// первый сегмент = всё до следующего "/" после ведущего слеша
	rest := next[1:]
	segEnd := strings.IndexByte(rest, '/')
	if segEnd == -1 {
		segEnd = len(rest)
	}
	if strings.Contains(rest[:segEnd], ":") {
		return "/"
	}

	return next
}
