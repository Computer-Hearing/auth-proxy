package gateway

import (
	"net/http"

	"auth-proxy/internal/authentik"
	"auth-proxy/internal/config"
	"auth-proxy/pkg/apierror"
)

// authorizeRoute проверяет доступ по required_groups маршрута.
// Пустой список групп - маршрут без проверки (Authentik уже отработал).
func (g *Gateway) authorizeRoute(w http.ResponseWriter, r *http.Request, route *config.RouteConfig, roles []string) bool {
	if len(route.RequiredGroups) == 0 {
		return true
	}

	id := authentik.FromContext(r.Context())
	authentik.WarnUnknown(g.logger, id.Username, roles, id.Groups)

	if id.Username == "" {
		apierror.HandleAPIError(w, g.logger, apierror.ErrUnauthorized)
		return false
	}

	if !authentik.Allows(roles, id.Groups, route.RequiredGroups) {
		g.logger.Debug("group access denied",
			"username", id.Username,
			"groups", id.Groups,
			"required_groups", route.RequiredGroups,
		)
		apierror.HandleAPIError(w, g.logger, apierror.ErrForbidden)
		return false
	}

	return true
}
