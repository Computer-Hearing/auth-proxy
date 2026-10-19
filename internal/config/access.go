package config

// AccessConfig - кто есть кто: роли и пользователи (общие для обоих сервисов).
type AccessConfig struct {
	// Roles - по возрастанию полномочий (слева направо), нужны для «лесенки» ролей
	Roles      []string `yaml:"roles" env:"ACCESS_ROLES" envDefault:"user,admin,superadmin" validate:"required,min=3,dive,required"`
	BcryptCost int      `yaml:"bcrypt_cost" env:"ACCESS_BCRYPT_COST" envDefault:"12" validate:"gte=4,lte=31"`
	Users      []User   `yaml:"users" validate:"dive"`
}

// User - пользователь из конфига. Пароль здесь в открытом виде,
// хешируется при загрузке в хранилище пользователей (users.FromConfig).
type User struct {
	ID       int64  `yaml:"id" json:"id" validate:"required,gte=1"`
	Login    string `yaml:"login" json:"login" validate:"required,min=4,max=128"`
	Password string `yaml:"password" json:"-" validate:"required,min=4,max=72"`
	Email    string `yaml:"email" json:"email" validate:"omitempty,email"`
	FullName string `yaml:"full_name" json:"full_name"`
	Role     string `yaml:"role" json:"role" validate:"required"`
}

// TopRole - самая главная роль (последняя в списке).
func (a *AccessConfig) TopRole() string {
	return a.Roles[len(a.Roles)-1]
}
