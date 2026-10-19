package users

import (
	"auth-proxy/internal/domain"
	"context"
	"fmt"
	"log/slog"

	"github.com/patrickmn/go-cache"
)

const (
	MinUsernameLen = 4
	MaxUsernameLen = 128
)

type Storage struct {
	cache  *cache.Cache
	logger *slog.Logger
}

func New(logger *slog.Logger) *Storage {
	if logger == nil {
		logger = slog.Default()
	}

	return &Storage{
		cache:  cache.New(cache.NoExpiration, cache.NoExpiration),
		logger: logger,
	}
}

// Load загружает пользователей в кеш
func (s *Storage) Load(_ context.Context, users []domain.User) {
	// Очищаем старый кеш
	s.cache.Flush()

	// слайс для того, чтобы в дебаг логе вывести имена пользователей который добавились в кеш
	var usersSlice = make([]slog.Attr, 0, len(users))
	for _, user := range users {
		// Кешируем по нескольким ключам
		s.cache.Set(idKey(user.ID), user, cache.NoExpiration)
		s.cache.Set(usernameKey(user.Username), user, cache.NoExpiration)

		// для лога
		usersSlice = append(usersSlice, slog.String(idKey(user.ID), user.Username))
	}

	s.logger.Debug("users loaded from config", slog.GroupAttrs("users", usersSlice...))
}

// GetByUsername получает пользователя по имени
func (s *Storage) GetByUsername(_ context.Context, username string) (*domain.User, bool) {
	if len(username) < MinUsernameLen || len(username) > MaxUsernameLen {
		s.logger.Warn("username too short", slog.String("username", username))
		return nil, false
	}

	val, found := s.cache.Get(usernameKey(username))
	if !found {
		s.logger.Warn("user not found by username", slog.String("username", username))
		return nil, false
	}
	user, ok := val.(domain.User)

	s.logger.Debug("get user by username", slog.String("username", username))
	return &user, ok
}

// GetByID получает пользователя по ID
func (s *Storage) GetByID(_ context.Context, id int64) (*domain.User, bool) {
	val, found := s.cache.Get(idKey(id))
	if !found {
		s.logger.Warn("user not found by id", slog.String("id", fmt.Sprint(id)))
		return nil, false
	}
	user, ok := val.(domain.User)

	s.logger.Debug("get user by id", slog.String("id", fmt.Sprint(id)))
	return &user, ok
}

// Authenticate проверяет логин и пароль
func (s *Storage) Authenticate(ctx context.Context, username, password string) (*domain.User, bool) {
	user, found := s.GetByUsername(ctx, username)
	if !found {
		return nil, false
	}

	if !user.CheckPassword(password) {
		s.logger.Debug("user check password failed", slog.String("username", username))
		return nil, false
	}

	s.logger.Debug("user authenticated", slog.String("username", username))
	return user, true
}

func idKey(id int64) string              { return fmt.Sprintf("user:id:%d", id) }
func usernameKey(username string) string { return fmt.Sprintf("user:username:%s", username) }
