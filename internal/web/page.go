package web

import (
	_ "embed"
	"net/http"
	"strings"
	"synovpn/internal/secure"
)

//go:embed ui.html
var page string

func (a *App) page(w http.ResponseWriter) {
	nonce := secure.Random(18)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'self'")
	w.Write([]byte(strings.ReplaceAll(page, "__NONCE__", nonce)))
}
