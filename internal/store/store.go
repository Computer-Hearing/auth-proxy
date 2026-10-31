package store

import (
	"slices"
	"sync/atomic"

	"auth-proxy/internal/config"
	"auth-proxy/internal/ruleengine"
)

// Snapshot - неизменяемое состояние маршрутов и ролей.
type Snapshot struct {
	Roles  []string
	Routes []config.RouteConfig
	Engine *ruleengine.Engine
}

// Store - атомарная подмена снапшота без блокировок на чтении.
type Store struct {
	ptr atomic.Pointer[Snapshot]
}

// New создаёт store с начальным снапшотом.
func New(s *Snapshot) *Store {
	st := &Store{}
	st.ptr.Store(s)
	return st
}

// Load возвращает текущий снапшот.
func (s *Store) Load() *Snapshot {
	return s.ptr.Load()
}

// Swap подменяет снапшот целиком.
func (s *Store) Swap(next *Snapshot) {
	s.ptr.Store(next)
}

// Build собирает снапшот из routes.yaml.
func Build(r *config.Routes, build ruleengine.Builder) (*Snapshot, error) {
	engine, err := ruleengine.New(r.Routes, build)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Roles:  slices.Clone(r.Roles),
		Routes: slices.Clone(r.Routes),
		Engine: engine,
	}, nil
}
