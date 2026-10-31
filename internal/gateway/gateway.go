package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"auth-proxy/internal/authentik"
	"auth-proxy/internal/middleware"
	"auth-proxy/internal/store"
	"auth-proxy/pkg/apierror"
	"auth-proxy/pkg/hostmatch"
	"auth-proxy/pkg/httpx"
)

// Options - зависимости гейта.
type Options struct {
	Logger       *slog.Logger
	Store        *store.Store
	AdminPort    int
	SecretHeader string
	AppVersion   string
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrStoreIsNil   = errors.New("store is nil")
)

// Gateway - основной http-слушатель: маршруты, проксирование и
// зарезервированные пути админки.
type Gateway struct {
	logger       *slog.Logger
	store        *store.Store
	admin        http.Handler
	secretHeader string
	appVersion   string
}

// New собирает гейт.
func New(opts *Options) (*Gateway, error) {
	if opts == nil {
		return nil, ErrOptionsIsNil
	}
	if opts.Store == nil {
		return nil, ErrStoreIsNil
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Gateway{
		logger:       logger,
		store:        opts.Store,
		admin:        newAdminProxy(opts.AdminPort),
		secretHeader: opts.SecretHeader,
		appVersion:   opts.AppVersion,
	}, nil
}

// Handler собирает mux гейта.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz(g.appVersion))

	// Пути админки зарезервированы: они обрабатываются раньше маршрутов
	// и проксируются на отдельный admin-листенер после проверки роли.
	admin := g.requireTopRole(g.admin)
	mux.Handle("/_admin", admin)
	mux.Handle("/_admin/", admin)
	mux.Handle("/config", admin)
	mux.Handle("/config/", admin)

	mux.Handle("/", g)

	return middleware.Chain(mux,
		middleware.Recover,
		middleware.RequestID,
		middleware.Log,
		authentik.Middleware(g.secretHeader),
	)
}

// ServeHTTP выбирает маршрут по host и пути, проверяет группы и проксирует.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := g.store.Load()
	host := requestHost(r)

	rule, ok := snap.Engine.Match(host, r.URL.Path)
	if !ok {
		g.logger.Debug("route not found",
			slog.String("host", host),
			slog.String("path", r.URL.Path),
			slog.String("remote", r.RemoteAddr),
		)
		apierror.HandleAPIError(w, g.logger, apierror.ErrPathNotFound)
		return
	}

	if !g.authorizeRoute(w, r, &rule.Route, snap.Roles) {
		return
	}

	g.logger.Debug("proxying",
		slog.String("host", host),
		slog.String("path", r.URL.Path),
		slog.String("target", rule.Route.Target),
	)
	rule.Upstream.ServeHTTP(w, r)
}

// requireTopRole пускает к админке только пользователя с roles[0].
func (g *Gateway) requireTopRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := g.store.Load()
		id := authentik.FromContext(r.Context())
		authentik.WarnUnknown(g.logger, id.Username, snap.Roles, id.Groups)

		if id.Username == "" {
			apierror.HandleAPIError(w, g.logger, apierror.ErrUnauthorized)
			return
		}
		if !authentik.IsTop(snap.Roles, id.Groups) {
			g.logger.Debug("admin access denied",
				slog.String("username", id.Username),
				slog.Any("groups", id.Groups),
			)
			apierror.HandleAPIError(w, g.logger, apierror.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestHost - host для выбора маршрута. За ingress (Caddy) исходный домен
// приходит в X-Forwarded-Host, поэтому он приоритетнее r.Host.
func requestHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = r.Host
	}
	return hostmatch.Normalize(host)
}

// newAdminProxy проксирует зарезервированные пути на admin-листенер.
func newAdminProxy(port int) http.Handler {
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	return httputil.NewSingleHostReverseProxy(target)
}
