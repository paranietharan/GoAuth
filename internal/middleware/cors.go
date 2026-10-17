package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAgeSeconds    int
}

func DefaultCORSConfig(allowedOrigins []string) CORSConfig {
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}
	return CORSConfig{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		AllowedHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		AllowCredentials: true,
		MaxAgeSeconds:    43200, // 12 hours
	}
}

func CORS(cfg CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowOrigin := ""

		for _, o := range cfg.AllowedOrigins {
			if o == "*" {
				allowOrigin = "*"
				break
			}
			if origin != "" && strings.EqualFold(o, origin) {
				allowOrigin = origin
				break
			}
		}

		if allowOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowOrigin)
			if allowOrigin != "*" && cfg.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
		c.Header("Access-Control-Max-Age", "43200")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
