package handler

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type HealthHandler struct {
	db    *sql.DB
	redis *redis.Client
}

func NewHealthHandler(db *sql.DB, redisClient *redis.Client) *HealthHandler {
	return &HealthHandler{db: db, redis: redisClient}
}

func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	checks := gin.H{
		"database": "up",
		"redis":    "up",
	}
	isReady := true

	if h.db != nil {
		if err := h.db.PingContext(ctx); err != nil {
			checks["database"] = "down: " + err.Error()
			isReady = false
		}
	} else {
		checks["database"] = "not_configured"
		isReady = false
	}

	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = "down: " + err.Error()
			isReady = false
		}
	} else {
		checks["redis"] = "not_configured"
		isReady = false
	}

	status := http.StatusOK
	state := "ready"
	if !isReady {
		status = http.StatusServiceUnavailable
		state = "unhealthy"
	}

	c.JSON(status, gin.H{
		"status": state,
		"checks": checks,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
