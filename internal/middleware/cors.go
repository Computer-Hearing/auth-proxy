package middleware

import (
	"net/http"
	"slices"
)

// CORS - разрешает кросс-доменные запросы для auth-сервиса.
// Логика (ровно по конфигу auth.allow_origins):
//   - список origins пуст -> полностью открыто:
//     Access-Control-Allow-Origin: * и Allow-Credentials: false;
//   - список не пуст -> только перечисленные origin, каждый echo-ится в ответ,
//     Allow-Credentials: true (с * браузер запретит куки). Чужой origin
//     не получает CORS-заголовков вовсе - браузер сам заблокирует запрос.
//
// Preflight (OPTIONS + Access-Control-Request-Method) обрабатывается здесь же,
// короткается до 204 и до самого обработчика не доходит.
func CORS(allowOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Запрос без Origin (не браузер/одно-доменный) - CORS не нужен
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// открытый режим: без списка разрешаем любому origin, но без кук
			if len(allowOrigins) == 0 {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Credentials", "false")
				if isPreflight(r) {
					writePreflight(w, r)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// точечный режим: разрешён только origin из списка
			if !slices.Contains(allowOrigins, origin) {
				// чужой origin - CORS-заголовки не ставим, ответ не читаем браузером
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
			if isPreflight(r) {
				writePreflight(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isPreflight - браузерный preflight перед реальным запросом:
// OPTIONS + заголовок, где перечислены метод и заголовки реального запроса.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// writePreflight отвечает на OPTIONS 204 со списком разрешённых методов
// и заголовков (echo запрошенных + свои служебные) и Access-Control-Max-Age.
func writePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	// перечисляем ровно те заголовки, которые попросил клиент
	if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
		w.Header().Set("Access-Control-Allow-Headers", requested)
	}
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}
