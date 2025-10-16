package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

func AuthMiddleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
				return
			}

			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
				http.Error(w, `{"error":"Invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := bearerToken[1]

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(jwtSecret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"Invalid token claims"}`, http.StatusUnauthorized)
				return
			}

			log.Printf("Claims: %+v", claims)

			userID, _ := claims["user_id"].(string)
			if !ok || userID == "" {
				http.Error(w, `{"error":"Invalid or missing user_id claim"}`, http.StatusUnauthorized)
				return
			}

			email, ok := claims["email"].(string)
			if !ok || email == "" {
				http.Error(w, `{"error":"Invalid or missing email claim"}`, http.StatusUnauthorized)
				return
			}

			var roleName string
			switch v := claims["role"].(type) {
			case string:
				roleName = v
			case map[string]interface{}:
				if n, ok := v["name"].(string); ok {
					roleName = n
				}
			}

			ctx := context.WithValue(r.Context(), "user_id", userID)
			ctx = context.WithValue(ctx, "email", email)
			ctx = context.WithValue(ctx, "role", roleName)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		log.Printf("Completed %s %s in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	visitors = make(map[string]*visitor)
	mu       sync.Mutex
)

func RateLimitMiddleware(next http.Handler) http.Handler {
	// Clean up old visitors every 5 minutes
	go cleanupVisitors()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		limiter := getVisitor(ip)

		if !limiter.Allow() {
			http.Error(w, `{"error":"Rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getVisitor(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	v, exists := visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(10, 20) // 10 requests per second, burst of 20
		visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func cleanupVisitors() {
	for {
		time.Sleep(5 * time.Minute)

		mu.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 10*time.Minute {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}

func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}

func RoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole := r.Context().Value("role")
			if userRole == nil {
				http.Error(w, `{"error":"Authorization required"}`, http.StatusUnauthorized)
				return
			}

			if userRole.(string) != requiredRole && userRole.(string) != "admin" {
				http.Error(w, `{"error":"Insufficient permissions"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func PermissionMiddleware(db *sql.DB, requiredPermission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := r.Context().Value("user_id")
			if userID == nil {
				http.Error(w, `{"error":"Authorization required"}`, http.StatusUnauthorized)
				return
			}

			var hasPermission bool
			query := `
				SELECT EXISTS (
					SELECT 1 FROM role_permissions rp
					INNER JOIN users u ON u.role_id = rp.role_id
					INNER JOIN permissions p ON p.id = rp.permission_id
					WHERE u.id = $1 AND p.name = $2
				)
			`
			err := db.QueryRow(query, userID, requiredPermission).Scan(&hasPermission)
			if err != nil || !hasPermission {
				http.Error(w, `{"error":"Insufficient permissions"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
