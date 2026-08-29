package pkg

import (
	"net"
	"net/http"
	"strings"

	"github.com/denisbrodbeck/machineid"
	"github.com/mileusna/useragent"
)

// DeviceFingerprint - структура отпечатка устройства
type DeviceFingerprint struct {
	UserAgent      string `json:"user_agent"`
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browser_version"`
	OS             string `json:"os"`
	Device         string `json:"device"`
	IsMobile       bool   `json:"is_mobile"`
	IsBot          bool   `json:"is_bot"`
	MachineID      string `json:"machine_id"`
	IP             string `json:"ip"`
	AcceptLanguage string `json:"accept_language"`
	AcceptEncoding string `json:"accept_encoding"`
}

func GetFingerprint(r *http.Request) DeviceFingerprint {
	ua := useragent.Parse(r.UserAgent())
	machineID, _ := machineid.ID()

	return DeviceFingerprint{
		UserAgent:      r.UserAgent(),
		Browser:        ua.Name,
		BrowserVersion: ua.Version,
		OS:             ua.OS,
		Device:         ua.Device,
		IsMobile:       ua.Mobile,
		IsBot:          ua.Bot,
		MachineID:      machineID,
		IP:             getRealIP(r),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		AcceptEncoding: r.Header.Get("Accept-Encoding"),
	}
}

// getRealIP получает реальный IP клиента с учетом прокси
func getRealIP(r *http.Request) string {
	// X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" && !isPrivateOrLoopback(ip) {
				return parseIP(ip)
			}
		}
		if len(ips) > 0 {
			return parseIP(strings.TrimSpace(ips[0]))
		}
	}

	// X-Real-IP (NGINX)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return parseIP(xri)
	}

	// True-Client-IP (Cloudflare)
	if tcip := r.Header.Get("True-Client-IP"); tcip != "" {
		return parseIP(tcip)
	}

	// CF-Connecting-IP (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return parseIP(cfip)
	}

	// RemoteAddr (fallback)
	return parseIP(r.RemoteAddr)
}

// parseIP извлекает чистый IP-адрес из строки, удаляя порт и обрабатывая все форматы
func parseIP(addr string) string {
	if addr == "" {
		return ""
	}

	// Удаляем порт (если есть)
	// Пример: "127.0.0.1:4325" -> "127.0.0.1"
	// Пример: "[::1]:8080" -> "::1" (IPv6)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}

	// Если не удалось разделить (нет порта), проверяем на IPv6 в квадратных скобках
	if strings.HasPrefix(addr, "[") && strings.Contains(addr, "]") {
		// Пример: "[::1]" -> "::1"
		addr = strings.TrimPrefix(addr, "[")
		addr = strings.TrimSuffix(addr, "]")
		return addr
	}

	// Если это уже чистый IP
	if net.ParseIP(addr) != nil {
		return addr
	}

	// Возвращаем как есть (но это невалидный IP)
	return addr
}

func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(parseIP(ipStr))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
