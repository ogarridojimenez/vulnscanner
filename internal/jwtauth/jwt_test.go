package jwtauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidate(t *testing.T) {
	m := New("test-secret-key-123", 15, 7)

	access, err := m.GenerateAccess("admin", "admin")
	if err != nil {
		t.Fatalf("GenerateAccess: %v", err)
	}
	if access == "" {
		t.Fatal("empty access token")
	}

	claims, err := m.Validate(access)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Username != "admin" {
		t.Errorf("username: got %q, want %q", claims.Username, "admin")
	}
	if claims.Role != "admin" {
		t.Errorf("role: got %q, want %q", claims.Role, "admin")
	}
}

func TestRefreshToken(t *testing.T) {
	m := New("test-secret", 15, 7)

	refresh, err := m.GenerateRefresh("user1")
	if err != nil {
		t.Fatalf("GenerateRefresh: %v", err)
	}

	claims, err := m.ValidateRefresh(refresh)
	if err != nil {
		t.Fatalf("ValidateRefresh: %v", err)
	}
	if claims.Subject != "user1" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "user1")
	}
}

func TestExpiredToken(t *testing.T) {
	m := New("test-secret", 15, 7)

	expiredClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		Username: "expired",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	tokenString, _ := token.SignedString(m.secret)

	_, err := m.Validate(tokenString)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	m := New("test-secret", 15, 7)

	_, err := m.Validate("invalid.token.string")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestWrongSecret(t *testing.T) {
	m1 := New("secret-1", 15, 7)
	m2 := New("secret-2", 15, 7)

	token, _ := m1.GenerateAccess("admin", "admin")
	_, err := m2.Validate(token)
	if err != ErrTokenInvalid {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}
