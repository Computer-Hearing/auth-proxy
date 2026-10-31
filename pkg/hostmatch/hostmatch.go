package hostmatch

import (
	"net"
	"strings"
)

// Match проверяет соответствие host-паттерна (точный host или wildcard
// одного уровня) хосту запроса: *.example.com матчит grafana.example.com,
// но не матчит a.b.example.com или example.com.
func Match(pattern, host string) bool {
	if IsWildcard(pattern) {
		base := pattern[2:] // "example.com"
		if !strings.HasSuffix(host, "."+base) {
			return false
		}
		subdomain := strings.TrimSuffix(host, "."+base)
		return subdomain != "" && !strings.Contains(subdomain, ".")
	}
	return pattern == host
}

// IsWildcard - паттерн вида *.example.com
func IsWildcard(pattern string) bool {
	return strings.HasPrefix(pattern, "*.")
}

// Normalize приводит host к виду для сравнения: без порта и в нижнем регистре.
// "Grafana.Example.com:443" -> "grafana.example.com", "[::1]:8080" -> "::1".
func Normalize(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.ToLower(host)
}

// NormalizeDomain нормализует домен для точного сравнения: без порта,
// в нижнем регистре и без хвостовой точки ("App.Example.com." -> "app.example.com").
func NormalizeDomain(host string) string {
	return strings.TrimSuffix(Normalize(host), ".")
}

// Set - набор допустимых host-паттернов (точные и *.wildcard).
type Set struct {
	patterns []string
}

// NewSet собирает набор, пустые паттерны пропускаются.
func NewSet(patterns ...string) Set {
	s := Set{patterns: make([]string, 0, len(patterns))}
	for _, p := range patterns {
		if p = Normalize(p); p != "" {
			s.patterns = append(s.patterns, p)
		}
	}
	return s
}

// Contains - подходит ли host (с портом или без) под один из паттернов.
func (s Set) Contains(host string) bool {
	host = Normalize(host)
	if host == "" {
		return false
	}
	for _, p := range s.patterns {
		if Match(p, host) {
			return true
		}
	}
	return false
}

// Patterns - паттерны набора (для логов).
func (s Set) Patterns() []string {
	return s.patterns
}
