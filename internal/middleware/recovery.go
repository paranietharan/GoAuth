package middleware

import (
	"log/slog"
	"net/http"

	apperrors "GoAuth/internal/errors"

	"github.com/gin-gonic/gin"
)

func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				reqID, _ := c.Get(RequestIDKey)
				if logger != nil {
					logger.Error("panic recovered",
						slog.Any("error", r),
						slog.Any("request_id", reqID),
						slog.String("path", c.Request.URL.Path),
						slog.String("method", c.Request.Method),
					)
				}
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": gin.H{
						"code":    apperrors.ErrInternal.Code,
						"message": apperrors.ErrInternal.Message,
					},
				})
			}
		}()
		c.Next()
	}
}
