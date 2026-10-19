package auth

import (
	"auth-proxy/internal/config"
	"auth-proxy/internal/domain"
	"auth-proxy/internal/middleware"
	"auth-proxy/internal/tokens"
	"auth-proxy/internal/users"
	"auth-proxy/pkg/apierror"
	"auth-proxy/pkg/httpx"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Options - зависимости auth-сервиса.
type Options struct {
	Logger       *slog.Logger
	Cookie       config.CookieConfig
	AllowOrigins []string
	// GatewayURL - внешний адрес гейта, туда возвращаем пользователя после логина
	GatewayURL string
	Tokens     *tokens.Service
	Users      *users.Storage
}

// Service - второй http-слушатель в бинарнике (отдельный порт).
// Занимается жизненным циклом кук: /login /refresh /logout и /user/me.
type Service struct {
	logger       *slog.Logger
	cookie       config.CookieConfig
	allowOrigins []string
	gatewayURL   string
	tokens       *tokens.Service
	users        *users.Storage
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrTokensIsNil  = errors.New("tokens service is nil")
	ErrUsersIsNil   = errors.New("users storage is nil")
)

func New(opts *Options) (*Service, error) {
	if opts == nil {
		return nil, ErrOptionsIsNil
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Tokens == nil {
		return nil, ErrTokensIsNil
	}
	if opts.Users == nil {
		return nil, ErrUsersIsNil
	}
	return &Service{
		logger:       opts.Logger,
		cookie:       opts.Cookie,
		allowOrigins: opts.AllowOrigins,
		gatewayURL:   opts.GatewayURL,
		tokens:       opts.Tokens,
		users:        opts.Users,
	}, nil
}

// Handler собирает mux auth-сервиса
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", httpx.Healthz(""))
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/refresh", s.handleRefresh)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/user/me", s.handleMe)
	mux.HandleFunc("/", s.handleHome)
	return middleware.Chain(mux, middleware.Recover, middleware.RequestID, middleware.Log,
		middleware.CORS(s.allowOrigins))
}

// handleLogin: GET - HTML-форма, POST - проверка пароля и установка кук.
func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := httpx.SafeNext(r.FormValue("next"))

	switch r.Method {
	case http.MethodGet:
		s.renderLoginForm(w, next, "")
		return
	case http.MethodPost:
		// Сверяем логин/пароль с хранилищем пользователей
		user, ok := s.users.Authenticate(r.Context(), r.FormValue("username"), r.FormValue("password"))
		if !ok {
			// Пароль не подошёл - возвращаем форму с ошибкой,
			// чтобы пользователь мог попробовать ещё раз
			s.renderLoginForm(w, next, "Неверный логин или пароль")
			return
		}

		// Выпускаем пару токенов и кладём в куки
		if err := s.issueTokens(w, user); err != nil {
			apierror.HandleAPIError(w, s.logger, err)
			return
		}

		// Возвращаем пользователя туда, куда он шёл изначально
		s.redirectBack(w, r, next)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRefresh обновляет пару токенов по refresh-куке.
// Может прийти и как GET (редирект из гейта) и как POST.
// Выдаём НОВЫЙ refresh (ротация), данные пользователя берём свежие из хранилища.
func (s *Service) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	next := httpx.SafeNext(r.FormValue("next"))

	// Refresh-куки нет - сессия завершена, отправляем на логин
	refreshCookie, err := r.Cookie(s.cookie.RefreshName)
	if err != nil {
		s.redirectLogin(w, r, next)
		return
	}

	// Refresh недействителен/истёк или пользователя больше нет - чистим куки и на логин
	userID, err := s.tokens.ValidateRefreshToken(refreshCookie.Value)
	if err != nil {
		s.clearAuthCookies(w)
		s.redirectLogin(w, r, next)
		return
	}
	user, ok := s.users.GetByID(r.Context(), userID)
	if !ok {
		s.clearAuthCookies(w)
		s.redirectLogin(w, r, next)
		return
	}

	if err := s.issueTokens(w, user); err != nil {
		s.clearAuthCookies(w)
		s.redirectLogin(w, r, next)
		return
	}
	s.redirectBack(w, r, next)
}

// handleLogout просто удаляет auth-куки и отвечает 204
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleMe отдаёт данные пользователя по access-куке (для фронта)
func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		apierror.HandleAPIError(w, s.logger, apierror.ErrUnauthorized)
		return
	}

	httpx.SendJSON(s.logger, w, user, http.StatusOK)
}

// handleHome - главная страница профиля на "/":
// залогиненный пользователь видит свои данные и кнопку выхода,
// аноним - предложение перейти на /login. Через ?error= код выводится
// поясняющий баннер (например, forbidden после редиректа с 403).
func (s *Service) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, loggedIn := s.currentUser(r)

	data := homeViewData{
		GatewayURL: s.gatewayURL,
	}
	if msg, ok := homeErrorText[r.FormValue("error")]; ok {
		data.Error = msg
		if role := r.FormValue("role"); role != "" && r.FormValue("error") == "forbidden" {
			data.Error += " Ваша роль: " + role
		}
	}
	if loggedIn {
		data.LoggedIn = true
		data.Username = user.Username
		data.Role = user.Role
		data.Email = user.Email
	}

	s.renderHome(w, data)
}

// issueTokens выпускает пару токенов пользователю и кладёт их в куки
func (s *Service) issueTokens(w http.ResponseWriter, user *domain.User) error {
	access, refresh, err := s.tokens.GenerateBothTokens(user.ID, user.Username, user.Email, user.Role)
	if err != nil {
		return err
	}
	s.setAuthCookies(w, access, refresh)
	return nil
}

// redirectBack возвращает пользователя НА ГЕЙТ: внешний адрес гейта
// (gatewayURL) + относительный next.
func (s *Service) redirectBack(w http.ResponseWriter, r *http.Request, next string) {
	location := strings.TrimSuffix(s.gatewayURL, "/") + next
	http.Redirect(w, r, location, http.StatusFound)
}

// redirectLogin - редирект на /login с сохранением next
func (s *Service) redirectLogin(w http.ResponseWriter, r *http.Request, next string) {
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
}

// currentUser достаёт пользователя по access-куке.
// Нет куки / токен невалиден / пользователя нет в кеше - возвращает false.
func (s *Service) currentUser(r *http.Request) (*domain.User, bool) {
	accessCookie, err := r.Cookie(s.cookie.AccessName)
	if err != nil {
		return nil, false
	}

	claims, err := s.tokens.ValidateAccessToken(accessCookie.Value)
	if err != nil {
		return nil, false
	}

	// Свежие данные берём из хранилища, а не из токена
	return s.users.GetByID(r.Context(), claims.UserID)
}
