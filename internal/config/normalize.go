package config

import "slices"

// Дефолтный суперадмин, если в конфиге нет пользователя с самой главной ролью
const (
	defaultSuperAdminLogin    = "superadmin"
	defaultSuperAdminPassword = "superadmin"
)

// normalize достраивает конфиг после валидации: дефолты маршрутов,
// «лесенка» ролей, дефолтный суперадмин, атрибуты кук.
func normalize(cfg *Config) {
	normalizeRoutes(cfg.Gateway.Routes, cfg.Access.Roles)
	ensureSuperAdmin(&cfg.Access)
	cfg.Session.Cookie.Secure = cfg.ENV == "production"
}

// normalizeRoutes проставляет auth_method по умолчанию и достраивает роли.
func normalizeRoutes(routes []RouteConfig, roles []string) {
	for i := range routes {
		route := &routes[i]

		// auth_method не указан - по умолчанию jwt
		if route.AuthMethod == "" {
			route.AuthMethod = AuthJWT
		}

		// Достраиваем роли "лесенкой": роли идут по возрастанию полномочий,
		// поэтому если роут открыт роли X, он должен быть открыт и всем ролям выше X.
		// Если у роута вообще нет ролей - открываем его для всех ролей.
		// Для none-маршрутов роли не нужны (проверки нет вовсе).
		if route.AuthMethod == AuthNone {
			continue
		}
		minIdx := 0
		if len(route.RequiredRoles) > 0 {
			minIdx = len(roles) - 1
			for _, role := range route.RequiredRoles {
				if idx := slices.Index(roles, role); idx < minIdx {
					minIdx = idx
				}
			}
		}
		route.RequiredRoles = slices.Clone(roles[minIdx:])
	}
}

// ensureSuperAdmin - если нет ни одного пользователя с самой главной ролью,
// добавляем дефолтного суперадмина (id = максимальный + 1).
func ensureSuperAdmin(access *AccessConfig) {
	top := access.TopRole()
	maxID := int64(0)
	for _, u := range access.Users {
		if u.Role == top {
			return
		}
		maxID = max(maxID, u.ID)
	}

	access.Users = append(access.Users, User{
		ID:       maxID + 1,
		Login:    defaultSuperAdminLogin,
		Password: defaultSuperAdminPassword,
		FullName: defaultSuperAdminLogin,
		Role:     top,
	})
}
