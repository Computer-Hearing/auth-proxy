package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type ctxKey int

const requestIDKey ctxKey = 0

// withRequestID кладёт request id в context
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// requestIDFrom достаёт request id из context (пусто, если его не было)
func requestIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// newRequestID генерирует случайный hex-идентификатор (16 байт).
// crypto/rand - чтобы нельзя было подобрать/подделать id.
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand практически никогда не падает; fallback на время
		return "unknown"
	}
	return hex.EncodeToString(b)
}
