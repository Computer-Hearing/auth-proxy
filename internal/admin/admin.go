package admin

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"auth-proxy/internal/authentik"
	"auth-proxy/internal/config"
	"auth-proxy/internal/middleware"
	"auth-proxy/internal/reverseproxy"
	"auth-proxy/internal/store"
	"auth-proxy/pkg/apierror"
	"auth-proxy/pkg/hostmatch"
	"auth-proxy/pkg/httpx"
)

const maxBody = 1 << 20 // 1 MiB

// Options - зависимости админки.
type Options struct {
	Logger       *slog.Logger
	Store        *store.Store
	RoutesPath   string
	SecretHeader string
	AppVersion   string
}

// Admin - отдельный http-слушатель: статика и JSON API управления routes.yaml.
type Admin struct {
	logger       *slog.Logger
	store        *store.Store
	routesPath   string
	secretHeader string
	appVersion   string
}

// New собирает админку.
func New(opts *Options) (*Admin, error) {
	if opts == nil {
		return nil, errors.New("options is nil")
	}
	if opts.Store == nil {
		return nil, errors.New("store is nil")
	}
	if opts.RoutesPath == "" {
		return nil, errors.New("routes path is empty")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Admin{
		logger:       logger,
		store:        opts.Store,
		routesPath:   opts.RoutesPath,
		secretHeader: opts.SecretHeader,
		appVersion:   opts.AppVersion,
	}, nil
}

// Handler собирает mux админки.
func (a *Admin) Handler() http.Handler {
	// Публичная ручка для Caddy on_demand_tls: без Authentik и проверки роли.
	root := http.NewServeMux()
	root.HandleFunc("/internal/allowed-domain", a.handleAllowedDomain)

	// Остальное - под аутентификацией и проверкой roles[0].
	protected := http.NewServeMux()
	protected.HandleFunc("/config", a.handleConfig)
	protected.Handle("/_admin/", http.StripPrefix("/_admin", a.staticHandler()))
	protected.Handle("/_admin", http.RedirectHandler("/_admin/", http.StatusFound))

	root.Handle("/", authentik.Middleware(a.secretHeader)(a.requireTopRole(protected)))

	return middleware.Chain(root,
		middleware.Recover,
		middleware.RequestID,
		middleware.Log,
	)
}

// handleAllowedDomain - публичная ручка для Caddy on_demand_tls.
// 200, если домен есть среди точных host маршрутов, иначе 404.
// Wildcard-маршруты и маршруты без host разрешения не дают.
func (a *Admin) handleAllowedDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := hostmatch.NormalizeDomain(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	snap := a.store.Load()
	_, allowed := snap.ExactHosts[domain]

	a.logger.Debug("allowed-domain",
		slog.String("domain", domain),
		slog.Bool("allowed", allowed),
	)

	if !allowed {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// requireTopRole пускает к админке только пользователя с roles[0].
func (a *Admin) requireTopRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := a.store.Load()
		id := authentik.FromContext(r.Context())
		authentik.WarnUnknown(a.logger, id.Username, snap.Roles, id.Groups)

		if id.Username == "" {
			apierror.HandleAPIError(w, a.logger, apierror.ErrUnauthorized)
			return
		}
		if !authentik.IsTop(snap.Roles, id.Groups) {
			apierror.HandleAPIError(w, a.logger, apierror.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleConfig - GET/PUT текущих ролей и маршрутов.
func (a *Admin) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap := a.store.Load()
		httpx.SendJSON(a.logger, w, config.Routes{
			Roles:  snap.Roles,
			Routes: snap.Routes,
		}, http.StatusOK)

	case http.MethodPut:
		a.updateRoutes(w, r)

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// updateRoutes валидирует, собирает снапшот, пишет routes.yaml и
// подменяет конфиг в памяти. При ошибке записи конфиг не меняется.
func (a *Admin) updateRoutes(w http.ResponseWriter, r *http.Request) {
	var body config.Routes

	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		httpx.SendError(a.logger, w, errors.New("invalid json: "+err.Error()), http.StatusBadRequest)
		return
	}

	if err := config.ValidateRoutes(&body); err != nil {
		httpx.SendError(a.logger, w, err, http.StatusBadRequest)
		return
	}

	// Нельзя отобрать доступ у себя: после сохранения caller должен
	// остаться с самой высокой ролью.
	id := authentik.FromContext(r.Context())
	if !authentik.IsTop(body.Roles, id.Groups) {
		httpx.SendError(a.logger, w, errors.New("new roles would revoke your admin access"), http.StatusBadRequest)
		return
	}

	snap, err := a.buildSnapshot(&body)
	if err != nil {
		httpx.SendError(a.logger, w, err, http.StatusBadRequest)
		return
	}

	if err := config.WriteRoutes(a.routesPath, &body); err != nil {
		a.logger.Error("write routes", slog.String("path", a.routesPath), slog.String("error", err.Error()))
		httpx.SendError(a.logger, w, errors.New("failed to persist routes"), http.StatusInternalServerError)
		return
	}

	a.store.Swap(snap)

	a.logger.Info("routes updated",
		slog.Int("roles", len(body.Roles)),
		slog.Int("routes", len(body.Routes)),
		slog.String("by", id.Username),
	)
	httpx.SendJSON(a.logger, w, body, http.StatusOK)
}

// buildSnapshot собирает движок маршрутов для новой конфигурации.
func (a *Admin) buildSnapshot(routes *config.Routes) (*store.Snapshot, error) {
	return store.Build(routes, func(route config.RouteConfig) (http.Handler, error) {
		return reverseproxy.New(route, a.logger)
	})
}
