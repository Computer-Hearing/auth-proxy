package config

// Routes - динамическая часть конфига (routes.yaml): роли и маршруты.
// Меняется через админку (GET/PUT /config) и применяется без рестарта.
type Routes struct {
	// Roles - по убыванию полномочий: Roles[0] - самая высокая.
	Roles  []string      `yaml:"roles" json:"roles" validate:"required,min=1,dive,required"`
	Routes []RouteConfig `yaml:"routes" json:"routes" validate:"dive"`
}

// RouteConfig - маршрут гейта.
type RouteConfig struct {
	Host             string `yaml:"host" json:"host"`
	Prefix           string `yaml:"prefix" json:"prefix" validate:"required"`
	Target           string `yaml:"target" json:"target" validate:"required,url"`
	Redirect         bool   `yaml:"redirect" json:"redirect"`
	StripFirstPrefix bool   `yaml:"strip_first_prefix" json:"strip_first_prefix"`

	// RequiredGroups - группы Authentik, которым доступен маршрут.
	// Пусто - маршрут без проверки группы (Authentik уже отработал на ingress).
	RequiredGroups []string `yaml:"required_groups" json:"required_groups" validate:"dive,required"`
}

// ReservedPrefixes - пути, занятые админкой. Маршруты не могут их использовать.
var ReservedPrefixes = []string{"/_admin", "/config"}
