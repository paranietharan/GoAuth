package middleware

import (
	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/model"

	"github.com/gin-gonic/gin"
)

func RequireRoles(allowedRoles ...model.Role) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		allowed[string(role)] = struct{}{}
	}

	return func(c *gin.Context) {
		roleVal, ok := c.Get("role")
		if !ok {
			apperrors.Write(c, apperrors.ErrForbidden)
			return
		}
		role, _ := roleVal.(string)
		if _, exists := allowed[role]; !exists {
			apperrors.Write(c, apperrors.ErrForbidden)
			return
		}
		c.Next()
	}
}
