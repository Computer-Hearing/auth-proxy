package pkg

import "strings"

// SafeNext - защита от open redirect.
//
// next приходит из query-параметра (?next=/важное/место), по нему auth-сервис
// редиректит после логина/обновления токена. Если принять любой адрес,
// злоумышленник сделает ссылку ?next=https://evil.com и уведёт туда после входа.
//
// Разрешаем только внутренний относительный путь:
//   - начинается с "/"
//   - не начинается с "//" (protocol-relative, тот же evil.com через //evil.com)
//   - первый сегмент пути не содержит ":" (http:, javascript: и т.п.)
//
// Не подходит - возвращаем "/" (жёсткий fallback вместо ошибки),
// чтобы авторизованному пользователю не показать ошибку.
func SafeNext(next string) string {
	if !strings.HasPrefix(next, "/") {
		return "/"
	}
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
