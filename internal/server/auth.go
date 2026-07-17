package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const sessionCookie = "vulnscan_session"

// uiAuth holds UI authentication state. If password is empty, auth is disabled.
type uiAuth struct {
	enabled  bool
	password string
	tokens   map[string]bool // valid session tokens
}

func newUIAuth(password string) *uiAuth {
	if password == "" {
		return &uiAuth{enabled: false}
	}
	return &uiAuth{
		enabled:  true,
		password: password,
		tokens:   make(map[string]bool),
	}
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loginPage renders the login form.
func (a *uiAuth) loginPage(c *gin.Context) {
	if !a.enabled {
		c.Redirect(http.StatusFound, "/")
		return
	}
	data, err := assets.ReadFile("static/login.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "asset not found")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

// handleLogin validates password and sets session cookie.
func (a *uiAuth) handleLogin(c *gin.Context) {
	if !a.enabled {
		c.Redirect(http.StatusFound, "/")
		return
	}
	password := c.PostForm("password")
	if password != a.password {
		c.Data(http.StatusOK, "text/html; charset=utf-8",
			[]byte(`<p style="color:red">Contraseña incorrecta</p><a href="/login">Volver</a>`))
		return
	}
	tok := randomToken()
	a.tokens[tok] = true
	c.SetCookie(sessionCookie, tok, 3600*24, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}

func (a *uiAuth) handleLogout(c *gin.Context) {
	if a.enabled {
		if tok, err := c.Cookie(sessionCookie); err == nil {
			delete(a.tokens, tok)
		}
	}
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}

// requireAuth middleware: redirects to /login if not authenticated.
func (a *uiAuth) requireAuth(c *gin.Context) {
	if !a.enabled {
		c.Next()
		return
	}
	tok, err := c.Cookie(sessionCookie)
	if err != nil || !a.tokens[tok] {
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
		return
	}
	c.Next()
}
