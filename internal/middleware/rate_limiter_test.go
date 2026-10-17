package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"GoAuth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func TestRateLimiterMemoryFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := middleware.NewRateLimiter(nil) // nil redis -> in-memory fallback

	r := gin.New()
	r.Use(limiter.Limit("test", 2, 2*time.Second))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 1st request -> OK
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 1st request status 200, got %d", w1.Code)
	}

	// 2nd request -> OK
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 2nd request status 200, got %d", w2.Code)
	}

	// 3rd request -> Rate limited (429)
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 3rd request status 429, got %d", w3.Code)
	}

	retryAfter := w3.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}
}
