package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)


func init() {
	secret := getJWTSecret()
	if string(secret) == "fallback-dev-secret-change-this-in-production" {
		log.Printf("⚠️ Using fallback JWT secret - set JWT_SECRET env var for security")
	} else {
		log.Printf("✅ Custom JWT secret loaded (length: %d)", len(secret))
	}
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// Context keys
type contextKey string

const userContextKey contextKey = "user"

// Get JWT secret from environment variable
func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		fmt.Println("WARNING: JWT_SECRET not set, using default (insecure for production)")
		return []byte("fallback-dev-secret-change-this-in-production")
	}
	return []byte(secret)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateToken(userID, email, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getJWTSecret())
}

// Add detailed logging to ValidateToken function
func ValidateToken(tokenString string) (*Claims, error) {
	log.Printf("🔍 Validating token: %s...", tokenString[:min(20, len(tokenString))])

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return getJWTSecret(), nil
	})

	if err != nil {
		log.Printf("❌ Token parsing failed: %v", err)
		return nil, err
	}

	if !token.Valid {
		log.Printf("❌ Token is invalid")
		return nil, fmt.Errorf("invalid token")
	}

	log.Printf("✅ Token validated successfully")
	log.Printf("📋 Claims - UserID: %s, Email: %s, Role: %s", claims.UserID, claims.Email, claims.Role)

	return claims, nil
}

// AuthMiddleware for use with gorilla/mux and net/http
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("🔐 AuthMiddleware: Processing request to %s", r.URL.Path)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("❌ No Authorization header found")
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		log.Printf("🔍 Authorization header: %s...", authHeader[:min(30, len(authHeader))])

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			log.Printf("❌ Invalid Authorization header format (missing Bearer prefix)")
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		log.Printf("🔍 Extracted token: %s...", tokenString[:min(20, len(tokenString))])

		claims, err := ValidateToken(tokenString)
		if err != nil {
			log.Printf("❌ Token validation failed: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		log.Printf("✅ Setting user in context: %s (%s)", claims.UserID, claims.Email)

		ctx := WithUser(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuthMiddleware - HTTP middleware that requires authentication
func RequireAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token from request
		claims, err := GetUserFromContext(r.Context())
		if err != nil {
			// Try to extract token from Authorization header
			token := r.Header.Get("Authorization")
			if token == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix if present
			if len(token) > 7 && token[:7] == "Bearer " {
				token = token[7:]
			}

			// Validate token
			claims, err = ValidateToken(token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), userContextKey, claims)
			r = r.WithContext(ctx)
		}

		// Call the next handler with the updated context
		next.ServeHTTP(w, r)
	})
}

// CONTEXT MANAGEMENT FUNCTIONS (consolidated from both files)

// WithUser adds user claims to context
func WithUser(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, userContextKey, claims)
}

// GetUserFromContext extracts user claims from context
func GetUserFromContext(ctx context.Context) (*Claims, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}

	user := ctx.Value(userContextKey)
	if user == nil {
		return nil, fmt.Errorf("user not found in context - authentication required")
	}

	claims, ok := user.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid user claims type in context")
	}

	if claims == nil {
		return nil, fmt.Errorf("user claims are nil")
	}

	return claims, nil
}

// GetUserIDFromContext retrieves just the user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	// Check if this is a public request first
	if IsPublicRequest(ctx) {
		return "" // No user ID for public requests
	}

	claims, err := GetUserFromContext(ctx)
	if err != nil {
		return ""
	}
	return claims.UserID
}

// GetUserEmailFromContext retrieves just the user email from context
func GetUserEmailFromContext(ctx context.Context) (string, error) {
	claims, err := GetUserFromContext(ctx)
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

// GetUserRoleFromContext retrieves just the user role from context
func GetUserRoleFromContext(ctx context.Context) (string, error) {
	claims, err := GetUserFromContext(ctx)
	if err != nil {
		return "", err
	}
	return claims.Role, nil
}

// IsAuthenticated checks if there's a valid user in context
func IsAuthenticated(ctx context.Context) bool {
	_, err := GetUserFromContext(ctx)
	return err == nil
}

// RequireAuth returns an error if user is not authenticated
func RequireAuth(ctx context.Context) (*Claims, error) {
	user, err := GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication required")
	}
	return user, nil
}

// RequireRole checks if user has the required role
func RequireRole(ctx context.Context, requiredRole string) (*Claims, error) {
	user, err := RequireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if user.Role != requiredRole {
		return nil, fmt.Errorf("insufficient permissions: required role %s, have %s", requiredRole, user.Role)
	}

	return user, nil
}

// RequireAdmin is a helper to check for admin role
func RequireAdmin(ctx context.Context) (*Claims, error) {
	return RequireRole(ctx, "ADMIN")
}

// HasRole checks if user has the specified role
func HasRole(ctx context.Context, role string) bool {
	claims, err := GetUserFromContext(ctx)
	if err != nil {
		return false
	}
	return claims.Role == role
}

// Add helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add this function at the end of your existing auth.go file

// IsPublicRequest checks if the request is in public context
func IsPublicRequest(ctx context.Context) bool {
	if ctx == nil {
		return false
	}

	isPublic, ok := ctx.Value("isPublic").(bool)
	return ok && isPublic
}
