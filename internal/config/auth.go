package config

// AuthConfig - auth-сервис (второй http-слушатель в том же бинарнике):
// /login /refresh /logout /user/me и страница профиля.
type AuthConfig struct {
	Port     int      `yaml:"port" env:"AUTH_PORT" envDefault:"6000" validate:"gte=1,lte=65535"`
	Timeouts Timeouts `yaml:",inline" envPrefix:"AUTH_"`
	// BaseURL - внешний адрес auth-сервиса (для Location в редиректах гейта)
	BaseURL string `yaml:"base_url" env:"AUTH_BASE_URL" validate:"required,url"`
	// AllowOrigins - CORS: список точных origin (scheme://host[:port])
	// Пусто = полностью открыто: Access-Control-Allow-Origin: * и Allow-Credentials: false.
	// Не пусто = только перечисленные origin и Allow-Credentials: true.
	AllowOrigins []string `yaml:"allow_origins" env:"AUTH_ALLOW_ORIGINS" validate:"omitempty,dive,url"`
	// AllowedRedirectHosts - куда ещё (кроме хоста gateway.base_url и host-ов
	// маршрутов) можно вернуть пользователя после логина. Точные хосты или
	// *.wildcard; нужно для доменов, которые обслуживают маршруты без host.
	AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts" env:"AUTH_ALLOWED_REDIRECT_HOSTS" validate:"dive,required"`
}
