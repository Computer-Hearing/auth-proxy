package auth

import (
	_ "embed"
	"html/template"
	"net/http"
)

// loginFormTemplate - HTML-форма входа, файл рядом (go:embed),
// на этапе сборки вкомпилируется в бинарь.
//
//go:embed login_form.html
var loginFormHTML string

var loginFormTemplate = template.Must(template.New("login").Parse(loginFormHTML))

//go:embed home.html
var homeHTML string

var homeFormTemplate = template.Must(template.New("home").Parse(homeHTML))

// homeErrorText - коды ошибок, которые принимает корневая страница,
// и их человекочитаемый текст. Всё остальное безопасно игнорируется.
var homeErrorText = map[string]string{
	"forbidden":    "Доступ запрещён: недостаточно прав для запрошенного маршрута.",
	"unauthorized": "Требуется вход в систему.",
}

type loginFormData struct {
	Next  string
	Error string
}

type homeViewData struct {
	LoggedIn   bool
	Error      string
	Username   string
	Role       string
	Email      string
	GatewayURL string
}

func (s *Service) renderLoginForm(w http.ResponseWriter, next, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginFormTemplate.Execute(w, loginFormData{Next: next, Error: errMsg}); err != nil {
		s.logger.Error("render login form", "error", err.Error())
	}
}

func (s *Service) renderHome(w http.ResponseWriter, data homeViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homeFormTemplate.Execute(w, data); err != nil {
		s.logger.Error("render home", "error", err.Error())
	}
}
