package routes

import (
	"auth-proxy/internal/config"
	"auth-proxy/pkg"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const redirectStatus = http.StatusFound

// routeEntry - обработка одного маршрута: либо реверс-прокси, либо редирект
type routeEntry struct {
	proxy      *httputil.ReverseProxy
	redirect   string
	stripFirst bool
}

// routePatternEntry - скомпилированный паттерн маршрута + его обработчик
type routePatternEntry struct {
	pattern *pkg.RoutePattern
	entry   routeEntry
}

// RoutesProxy - маршрутизатор: путь -> обработчик маршрута (прокси/редирект)
type RoutesProxy struct {
	routes []routePatternEntry
}

// NewRoutesProxy строит список маршрутов с паттернами из конфига
func NewRoutesProxy(cfg *config.Config) (*RoutesProxy, error) {
	if cfg == nil {
		return nil, fmt.Errorf("routes config is nil")
	}

	routes := make([]routePatternEntry, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		pattern, err := pkg.CachedRoutePattern(route.Prefix)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", route.Prefix, err)
		}

		entry := routeEntry{
			stripFirst: route.StripFirstPrefix,
		}

		if route.Redirect {
			entry.redirect = route.Target
		} else {
			proxy, err := pkg.NewReverseProxy(route.Target, route.StripFirstPrefix)
			if err != nil {
				return nil, fmt.Errorf("create reverse proxy for route %s: %w", route.Prefix, err)
			}
			entry.proxy = proxy
		}

		routes = append(routes, routePatternEntry{pattern: pattern, entry: entry})
	}

	return &RoutesProxy{routes: routes}, nil
}

// entry находит обработчик по самому специфичному совпавшему паттерну:
// длиннее литеральная часть -> длиннее паттерн -> раньше в конфиге.
// Первый совпавший маршрут при равной специфичности и есть самый ранний в конфиге.
func (rp *RoutesProxy) entry(path string) (routeEntry, bool) {
	var best *routeEntry
	var bestPattern *pkg.RoutePattern

	for _, re := range rp.routes {
		if !re.pattern.Match(path) {
			continue
		}
		if best == nil || re.pattern.MoreSpecific(bestPattern) {
			entry := re.entry
			best = &entry
			bestPattern = re.pattern
		}
	}

	if best == nil {
		return routeEntry{}, false
	}
	return *best, true
}

// Proxy возвращает ReverseProxy для пути по самому специфичному совпавшему паттерну
func (rp *RoutesProxy) Proxy(path string) *httputil.ReverseProxy {
	entry, ok := rp.entry(path)
	if !ok {
		return nil
	}
	return entry.proxy
}

// ServeHTTP проксирует запрос или редиректит на целевой сервис
func (rp *RoutesProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	entry, ok := rp.entry(r.URL.Path)
	if !ok {
		http.Error(w, "path not found in config", http.StatusNotFound)
		return
	}

	if entry.redirect != "" {
		rp.redirect(w, r, entry)
		return
	}

	entry.proxy.ServeHTTP(w, r)
}

// redirect отдает 302 на target + путь запроса (при stripFirst - без первого сегмента)
func (rp *RoutesProxy) redirect(w http.ResponseWriter, r *http.Request, entry routeEntry) {
	target, err := url.Parse(entry.redirect)
	if err != nil {
		http.Error(w, "invalid redirect target", http.StatusInternalServerError)
		return
	}

	path := r.URL.Path
	if entry.stripFirst {
		path = pkg.StripFirstPath(path)
	}

	target.Path = joinPaths(target.Path, path)
	target.RawPath = ""
	http.Redirect(w, r, target.String(), redirectStatus)
}

// joinPaths склеивает путь target и подпуть запроса с одним слешем
func joinPaths(base, sub string) string {
	if base == "" {
		return sub
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(sub, "/")
}
