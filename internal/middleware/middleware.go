package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusRecorder перехватывает статус и размер ответа,
// чтобы их можно было залогировать после обработки запроса.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// RequestID - роутит X-Request-ID из заголовка
var RequestIDHeader = "X-Request-ID"

// RequestID добавляет (если ещё нет) X-Request-ID в каждый запрос и кладёт
// его в лог, чтобы можно было связать запись от гейта и auth-сервиса.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		r.Header.Set(RequestIDHeader, id)

		ctx := withRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Recover превращает панику в обработчике в логируемый 500,
// чтобы она не уходила в http.Server (который просто закрыл бы соединение).
func Recover(next http.Handler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				logger.Error("panic recovered",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Any("panic", p),
					slog.String("stack", string(debug.Stack())),
					slog.String("request_id", requestIDFrom(r.Context())),
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Log логирует каждый запрос:
// status, полный путь (с query), длительность, method, remote, user-agent.
func Log(next http.Handler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()

		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		attrs := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.RequestURI()),
			slog.Int("status", rec.status),
			slog.Int64("bytes", int64(rec.bytes)),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.String("remote", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
			slog.String("request_id", requestIDFrom(r.Context())),
		}

		// 5xx - это Warning, всё остальное - Info
		if rec.status >= 500 {
			logger.Warn("http request", attrs...)
			return
		}
		logger.Info("http request", attrs...)
	})
}

// Chain применяет мидлвары в порядке слева направо:
// Chain(h, A, B) = A(B(handler))
func Chain(handler http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}
