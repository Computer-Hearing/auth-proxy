package auth

import "net/http"

// setAuthCookies выставляет access и refresh куки.
// Path "/" - действуют на весь домен (и на гейт тоже, куки не зависят от порта).
// HttpOnly - JS их не прочитает, SameSite=Lax - защита от CSRF.
func (s *Service) setAuthCookies(w http.ResponseWriter, access, refresh string) {
	http.SetCookie(w, s.newCookie(s.cookie.AccessName, access))
	http.SetCookie(w, s.newCookie(s.cookie.RefreshName, refresh))
}

// clearAuthCookies удаляет обе куки (MaxAge<0 заставляет браузер выкинуть их)
func (s *Service) clearAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{s.cookie.AccessName, s.cookie.RefreshName} {
		c := s.newCookie(name, "")
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
}

func (s *Service) newCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   s.cookie.Domain,
		HttpOnly: true,
		Secure:   s.cookie.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}
