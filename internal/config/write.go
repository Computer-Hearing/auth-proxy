package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WriteRoutes атомарно пишет routes.yaml: временный файл в том же каталоге
// и rename. При ошибке на любом шаге исходный файл остаётся нетронутым.
func WriteRoutes(path string, routes *Routes) error {
	data, err := yaml.Marshal(routes)
	if err != nil {
		return fmt.Errorf("marshal routes: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create routes dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".routes-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp routes: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp routes: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp routes: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp routes: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp routes: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename routes: %w", err)
	}
	return nil
}
