package users

import (
	"auth-proxy/internal/domain"
	"auth-proxy/pkg"
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/patrickmn/go-cache"
)

type UserStorageConfig struct {
	Logger *slog.Logger
}

type UserStorage struct {
	cache  *cache.Cache
	mu     sync.RWMutex
	logger *slog.Logger
}

func NewUsersCache(cfg *UserStorageConfig) *UserStorage {
	if cfg == nil {
		panic("users cache config is nil")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &UserStorage{
		cache:  cache.New(cache.NoExpiration, cache.NoExpiration),
		logger: cfg.Logger,
		mu:     sync.RWMutex{},
	}
}

// LoadUsers загружает пользователей в кеш
func (uc *UserStorage) LoadUsers(_ context.Context, users []domain.User) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Очищаем старый кеш
	uc.cache.Flush()

	// слайс для того, чтобы в дебаг логе вывести имена пользователей который добавились в кеш
	var usersSlice = make([]slog.Attr, 0, len(users))
	for _, user := range users {
		// Кешируем по нескольким ключам
		uc.cache.Set(fmt.Sprintf("user:id:%d", user.ID), user, cache.NoExpiration)
		uc.cache.Set(fmt.Sprintf("user:username:%s", user.Username), user, cache.NoExpiration)
		uc.cache.Set(fmt.Sprintf("user:email:%s", user.Email), user, cache.NoExpiration)

		// для лога
		usersSlice = append(usersSlice,
			slog.String(fmt.Sprintf("user:id:%d", user.ID), user.Username))
	}

	uc.logger.Debug("users loaded from config", slog.GroupAttrs("users", usersSlice...))
}

// GetByUsername получает пользователя по имени
func (uc *UserStorage) GetByUsername(_ context.Context, username string) (*domain.User, bool) {
	if len(username) < pkg.MinUsernameLen || len(username) > pkg.MaxUsernameLen {
		return nil, false
	}

	val, found := uc.cache.Get(fmt.Sprintf("user:username:%s", username))
	if !found {
		return nil, false
	}
	user, ok := val.(domain.User)
	return &user, ok
}

// GetByEmail получает пользователя по email
func (uc *UserStorage) GetByEmail(_ context.Context, email string) (*domain.User, bool) {
	val, found := uc.cache.Get(fmt.Sprintf("user:email:%s", email))
	if !found {
		return nil, false
	}
	user, ok := val.(domain.User)
	return &user, ok
}

// GetByID получает пользователя по ID
func (uc *UserStorage) GetByID(_ context.Context, id int64) (*domain.User, bool) {
	val, found := uc.cache.Get(fmt.Sprintf("user:id:%d", id))
	if !found {
		return nil, false
	}
	user, ok := val.(domain.User)
	return &user, ok
}

// Authenticate проверяет логин и пароль
func (uc *UserStorage) Authenticate(ctx context.Context, username, password string) (*domain.User, bool) {
	user, found := uc.GetByUsername(ctx, username)
	if !found {
		return nil, false
	}

	if !user.CheckPassword(password) {
		return nil, false
	}

	return user, true
}

// AddOrUpdate добавляет или обновляет пользователя
func (uc *UserStorage) AddOrUpdate(_ context.Context, user domain.User) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Обновляем все ключи
	uc.cache.Set(fmt.Sprintf("user:id:%d", user.ID), user, cache.NoExpiration)
	uc.cache.Set(fmt.Sprintf("user:username:%s", user.Username), user, cache.NoExpiration)
	uc.cache.Set(fmt.Sprintf("user:email:%s", user.Email), user, cache.NoExpiration)
}

// Delete удаляет пользователя
func (uc *UserStorage) Delete(ctx context.Context, id int64) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	user, found := uc.GetByID(ctx, id)
	if !found {
		return
	}

	uc.cache.Delete(fmt.Sprintf("user:id:%d", user.ID))
	uc.cache.Delete(fmt.Sprintf("user:username:%s", user.Username))
	uc.cache.Delete(fmt.Sprintf("user:email:%s", user.Email))
}

// GetAll возвращает всех пользователей
func (uc *UserStorage) GetAll(_ context.Context) []domain.User {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	var users []domain.User
	items := uc.cache.Items()

	for key, item := range items {
		// Берем только ключи с "user:id:"
		// тут можно по любому id/username/email взял по логике id
		if len(key) > 8 && key[:8] == "user:id:" {
			if user, ok := item.Object.(domain.User); ok {
				users = append(users, user)
			}
		}
	}

	return users
}
