package pkg

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// RoutePattern - скомпилированный шаблон маршрута.
// Синтаксис: литералы, * (один сегмент) и ** (любое число сегментов).
// Паттерн матчит начало пути (prefix-семантика), хвост не важен.
type RoutePattern struct {
	raw string
	re  *regexp.Regexp
	// head - литеральная часть до первой звездочки, используется для приоритета
	head string
}

var patternCache sync.Map // map[string]*RoutePattern

// ParseRoutePattern собирает RoutePattern из префикса вида "/api/*/v1/**".
// Задача: перевести путь с * и ** в строку регулярного выражения,
// подставив вместо них спецсимволы.
// Для * будет [^/]* - оно значит: любой текст до нахождения первого слеша, api/*/v1 -> api/[^/]*/v1 -> любой текст
// вместо этого спец символа до момента нахождения первого слеша: api/admin/v1 - матчит, api/admin/net/v1 - уже не матчит
// Для ** будет .* - оно значит: любой текст может стоять на этом месте вместо спец символа, прям любой
// Например: api/.*/v1 -> api/1/1/1/1/1/v1 заматчит
func ParseRoutePattern(prefix string) (*RoutePattern, error) {
	// Валидация
	if prefix == "" {
		return nil, fmt.Errorf("route prefix is empty")
	}
	if prefix[0] != '/' {
		return nil, fmt.Errorf("route prefix %q must start with '/'", prefix)
	}

	// сама строка регулярного выражения
	var b strings.Builder
	// ^ символ начала строки. Например, ^Привет заматчит "Привет мир", но не заматчит "Мир Привет" - не начало строки
	b.WriteString("^")

	// Head - строка до первой *, например: api/v1/*/admin тут head будет api/v1/
	var head strings.Builder
	headDone := false

	// Скан литералов, ** и *
	for i := 0; i < len(prefix); {
		// идем до первого * где спец символ вставлять будем
		if prefix[i] == '*' {
			// нашли первую * — head уже собран, дальше его не пополняем
			if !headDone {
				headDone = true
			}
			// если не конец строки и это двойная звездочка, то есть **
			if i+1 < len(prefix) && prefix[i+1] == '*' {
				// записываем нужный спец символ
				b.WriteString(".*")
				// пропускаем **
				i += 2
			} else {
				// если не ** а * то также вставляем нужный спец символ и идем дальше
				b.WriteString("[^/]*")
				i++
			}
			// continue: не даём '*' попасть в ветку литералов ниже
			continue
		}

		// другая переменная чтобы i не испортить
		j := i
		// идем пока не найдем первую *
		for j < len(prefix) && prefix[j] != '*' {
			j++
		}
		// получаем эту строку
		lit := prefix[i:j]
		// если это до первой *, то есть шапки нет, то создаем ее
		if !headDone {
			head.WriteString(lit)
		}
		// Экранируем литералы (QuoteMeta), чтобы . + ( и прочие спецсимволы regexp
		// означали сами себя: /api/v1.x не станет "любая буква" по месту точки
		b.WriteString(regexp.QuoteMeta(lit))
		// i = j: литерал уже разобран, продолжаем с места, где остановился j
		i = j
	}

	// компилируем итоговое регулярное выражение
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("compile route pattern %q: %w", prefix, err)
	}

	return &RoutePattern{raw: prefix, re: re, head: head.String()}, nil
}

// CachedRoutePattern возвращает скомпилированный паттерн, кешируя результат.
func CachedRoutePattern(prefix string) (*RoutePattern, error) {
	if v, ok := patternCache.Load(prefix); ok {
		return v.(*RoutePattern), nil
	}

	p, err := ParseRoutePattern(prefix)
	if err != nil {
		return nil, err
	}
	patternCache.Store(prefix, p)
	return p, nil
}

// Match проверяет, что path начинается с совпадения паттерна.
func (p *RoutePattern) Match(path string) bool {
	return p.re.MatchString(path)
}

// HeadLen - длина литеральной части до первой звездочки (для приоритета).
func (p *RoutePattern) HeadLen() int {
	return len(p.head)
}

// PatternLen - длина исходного паттерна (для приоритета при равном head).
func (p *RoutePattern) PatternLen() int {
	return len(p.raw)
}

// MoreSpecific - истина, если p приоритетнее b при совпадении с одним путём:
// сначала длиннее литеральная голова, затем длиннее паттерн.
// При полном равенстве решает порядок в конфиге (на стороне вызывающего).
func (p *RoutePattern) MoreSpecific(b *RoutePattern) bool {
	if p.HeadLen() != b.HeadLen() {
		return p.HeadLen() > b.HeadLen()
	}
	return p.PatternLen() > b.PatternLen()
}
