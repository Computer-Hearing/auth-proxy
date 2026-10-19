package ruleengine

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg/hostmatch"
	"auth-proxy/pkg/routepattern"
	"cmp"
	"fmt"
	"net/http"
	"slices"
)

// Rule - скомпилированный маршрут: настройки из конфига (auth_method,
// required_roles, ...) и готовый обработчик, куда отдать запрос после авторизации.
type Rule struct {
	Route    config.RouteConfig
	Upstream http.Handler
	pattern  *routepattern.Pattern
	// host - host маршрута в виде для сравнения (без порта, в нижнем регистре)
	host string
	// hostRank - насколько точно маршрут привязан к домену:
	// точный host > *.wildcard > без host
	hostRank int
}

const (
	rankAnyHost = iota
	rankWildcardHost
	rankExactHost
)

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
		host := hostmatch.Normalize(route.Host)
		rules = append(rules, &Rule{
			Route:    route,
			Upstream: upstream,
			pattern:  pattern,
			host:     host,
			hostRank: hostRank(host),
		})
	}

	// Сортируем по приоритету, тогда Match берёт первое совпадение.
	// Стабильная сортировка: при полной ничьей решает порядок в конфиге.
	slices.SortStableFunc(rules, func(a, b *Rule) int {
		return cmp.Or(
			cmp.Compare(b.hostRank, a.hostRank),
			cmp.Compare(b.pattern.HeadLen(), a.pattern.HeadLen()),
			cmp.Compare(b.pattern.PatternLen(), a.pattern.PatternLen()),
		)
	})
	return &Engine{rules: rules}, nil
}

func hostRank(host string) int {
	switch {
	case host == "":
		return rankAnyHost
	case hostmatch.IsWildcard(host):
		return rankWildcardHost
	default:
		return rankExactHost
	}
}

// Match ищет маршрут по host и пути. Сначала домен, потом путь:
//  1. самый точный host: точный > *.wildcard > маршрут без host;
//  2. среди них самый специфичный префикс: длиннее литеральная часть,
//     затем длиннее паттерн;
//  3. при полной ничьей - раньше в конфиге.
//
// Если у домена нет маршрута под этот путь, берётся следующий уровень:
// wildcard, затем маршруты без host (общий fallback).
// host ожидается уже нормализованным (hostmatch.Normalize).
func (e *Engine) Match(host, path string) (*Rule, bool) {
	for _, rule := range e.rules {
		if rule.host != "" && !hostmatch.Match(rule.host, host) {
			continue
		}
		if rule.pattern.Match(path) {
			return rule, true
		}
	}
	return nil, false
}
