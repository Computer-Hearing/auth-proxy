package ruleengine

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg/routepattern"
	"fmt"
	"net/http"
	"strings"
)

// Rule - скомпилированный маршрут: настройки из конфига (auth_method,
// required_roles, ...) и готовый обработчик, куда отдать запрос после авторизации.
type Rule struct {
	Route    config.RouteConfig
	Upstream http.Handler
	pattern  *routepattern.Pattern
}

// Builder строит обработчик для маршрута (в гейте - reverseproxy.New).
type Builder func(route config.RouteConfig) (http.Handler, error)

// Engine выбирает маршрут для запроса. Права и проксирование берутся
// из одного и того же Rule, поэтому разойтись им негде.
type Engine struct {
	rules []*Rule
}

// New компилирует маршруты один раз при старте.
func New(routes []config.RouteConfig, build Builder) (*Engine, error) {
	rules := make([]*Rule, 0, len(routes))
	for _, route := range routes {
		pattern, err := routepattern.Parse(route.Prefix)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", route.Prefix, err)
		}
		upstream, err := build(route)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", route.Prefix, err)
		}
		rules = append(rules, &Rule{Route: route, Upstream: upstream, pattern: pattern})
	}
	return &Engine{rules: rules}, nil
}

// Match ищет маршрут по host и пути (самое специфичное совпадение:
// длиннее литеральная часть, затем длиннее паттерн, затем раньше в конфиге).
// Первый совпавший маршрут при равной специфичности и есть самый ранний в конфиге.
func (e *Engine) Match(host, path string) (*Rule, bool) {
	var best *Rule

	for _, rule := range e.rules {
		routeHost := rule.Route.Host
		// Проверяем host (если задан в маршруте)
		if routeHost != "" && !matchHost(routeHost, host) {
			continue
		}
		if !rule.pattern.Match(path) {
			continue
		}

		// Приоритет: более специфичный префикс > точный host > wildcard host > пустой host
		if best == nil || rule.pattern.MoreSpecific(best.pattern) ||
			(routeHost != "" && best.Route.Host == "") ||
			(routeHost != "" && !isWildcard(routeHost) && isWildcard(best.Route.Host)) {
			best = rule
		}
	}

	return best, best != nil
}

// matchHost проверяет соответствие host маршрута заголовку Host запроса.
// Поддерживает wildcard одного уровня: *.example.com матчит grafana.example.com,
// но не матчит a.b.example.com или example.com.
func matchHost(routeHost, requestHost string) bool {
	if isWildcard(routeHost) {
		base := routeHost[2:] // "example.com"
		if !strings.HasSuffix(requestHost, "."+base) {
			return false
		}
		subdomain := strings.TrimSuffix(requestHost, "."+base)
		return subdomain != "" && !strings.Contains(subdomain, ".")
	}
	return routeHost == requestHost
}

func isWildcard(host string) bool {
	return strings.HasPrefix(host, "*.")
}
