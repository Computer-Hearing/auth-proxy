package auth

import (
	_ "embed" // для //go:embed login_form.html

	"auth-proxy/internal/config"
	"auth-proxy/internal/modules/tokens"
	"auth-proxy/internal/modules/users"
	"auth-proxy/pkg"
	"auth-proxy/pkg/apierror"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Options - зависимости auth-сервиса.
type Options struct {
	Logger *slog.Logger
	Config *config.Config
	JWT    *tokens.JWTModule
	Users  users.UserStorage
}

// Service - второй http-слушатель в бинарнике (отдельный порт).
// Занимается жизненным циклом кук: /login /refresh /logout и /user/me.
type Service struct {
	cfg    *config.Config
	logger *slog.Logger
	jwt    *tokens.JWTModule
	users  users.UserStorage
}

var (
	ErrOptionsIsNil = errors.New("options is nil")
	ErrConfigIsNil  = errors.New("config is nil")
	ErrJWTIsNil     = errors.New("jwt module is nil")
	ErrUsersIsNil   = errors.New("users storage is nil")
)

func New(opts *Options) (*Service, error) {
	if opts == nil {
		return nil, ErrOptionsIsNil
	}
	if opts.Config == nil {
		return nil, ErrConfigIsNil
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.JWT == nil {
		return nil, ErrJWTIsNil
	}
	// UserStorage - структура по значению; нулевое значение == "не передан"
	if opts.Users == (users.UserStorage{}) {
		return nil, ErrUsersIsNil
	}
	return &Service{cfg: opts.Config, logger: opts.Logger, jwt: opts.JWT, users: opts.Users}, nil
}

// Handler собирает mux auth-сервиса
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/refresh", s.handleRefresh)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/user/me", s.handleMe)
	return mux
}

// handleLogin: GET - HTML-форма, POST - проверка пароля и установка кук.
func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := pkg.SafeNext(r.FormValue("next"))

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
		access, refresh, err := s.jwt.GenerateBothTokens(user.ID, user.Username, user.Email, user.Role)
		if err != nil {
			apierror.HandleAPIError(w, s.logger, err)
			return
		}
		s.setAuthCookies(w, access, refresh)

		// Возвращаем пользователя туда, куда он шёл изначально
		s.redirectBack(w, r, next)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRefresh обновляет пару токенов по refresh-куке.
// Может прийти и как GET (редирект из гейта) и как POST.
func (s *Service) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	next := pkg.SafeNext(r.FormValue("next"))

	// Refresh-куки нет - сессия завершена, отправляем на логин
	refreshCookie, err := r.Cookie(s.cfg.JWT.RefreshCookieKey)
	if err != nil {
		s.redirectLogin(w, r, next)
		return
	}

	access, refresh, err := s.jwt.RefreshTokens(refreshCookie.Value)
	if err != nil {
		// Refresh недействителен/истёк - чистим куки и на логин
		s.clearAuthCookies(w)
		s.redirectLogin(w, r, next)
		return
	}

	s.setAuthCookies(w, access, refresh)
	s.redirectBack(w, r, next)
}

// handleLogout гасит обе куки и возвращает на next (или на "/")
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	next := pkg.SafeNext(r.FormValue("next"))
	s.clearAuthCookies(w)
	s.redirectBack(w, r, next)
}

// redirectBack возвращает пользователя НА ГЕЙТ: внешний адрес гейта
// (cfg.Gateway.BaseURL) + относительный next.
// next берём строго относительным (SafeNext), поэтому host всегда из конфига,
// а не из запроса - open redirect невозможен.
func (s *Service) redirectBack(w http.ResponseWriter, r *http.Request, next string) {
	location := strings.TrimSuffix(s.cfg.Gateway.BaseURL, "/") + next
	http.Redirect(w, r, location, http.StatusFound)
}

// handleMe отдаёт данные пользователя по access-куке (для фронта)
func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	accessCookie, err := r.Cookie(s.cfg.JWT.AccessCookieKey)
	if err != nil {
		apierror.HandleAPIError(w, s.logger, apierror.ErrUnauthorized)
		return
	}

	claims, err := s.jwt.ValidateAccessToken(accessCookie.Value)
	if err != nil {
		apierror.HandleAPIError(w, s.logger, apierror.ErrUnauthorized)
		return
	}

	// Свежие данные берём из хранилища, а не из токена
	user, ok := s.users.GetByID(r.Context(), claims.UserID)
	if !ok {
		apierror.HandleAPIError(w, s.logger, apierror.ErrUnauthorized)
		return
	}

	pkg.SendJSON(s.logger, w, user, http.StatusOK)
}

// redirectLogin - редирект на /login с сохранением next
func (s *Service) redirectLogin(w http.ResponseWriter, r *http.Request, next string) {
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
}

// setAuthCookies выставляет access и refresh куки.
// Path "/" - действуют на весь домен (и на гейт тоже, куки не зависят от порта).
// HttpOnly - JS их не прочитает, SameSite=Lax - защита от CSRF.
func (s *Service) setAuthCookies(w http.ResponseWriter, access, refresh string) {
	s.setCookie(w, s.cfg.JWT.AccessCookieKey, access)
	s.setCookie(w, s.cfg.JWT.RefreshCookieKey, refresh)
}

// clearAuthCookies удаляет обе куки (MaxAge<0 заставляет браузер выкинуть их)
func (s *Service) clearAuthCookies(w http.ResponseWriter) {
	s.clearCookie(w, s.cfg.JWT.AccessCookieKey)
	s.clearCookie(w, s.cfg.JWT.RefreshCookieKey)
}

func (s *Service) setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.ENV == "production",
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Secure:   s.cfg.ENV == "production",
		SameSite: http.SameSiteLaxMode,
	})
}

// loginFormTemplate - HTML-форма входа, файл рядом (go:embed),
// на этапе сборки вкомпилируется в бинарь.
//
//go:embed login_form.html
var loginFormHTML string

var loginFormTemplate = template.Must(template.New("login").Parse(loginFormHTML))

type loginFormData struct {
	Next  string
	Error string
}

func (s *Service) renderLoginForm(w http.ResponseWriter, next, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginFormTemplate.Execute(w, loginFormData{Next: next, Error: errMsg}); err != nil {
		s.logger.Error("render login form", "error", err.Error())
	}
}
