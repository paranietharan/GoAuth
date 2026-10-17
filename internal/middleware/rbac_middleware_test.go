package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"GoAuth/internal/middleware"
	"GoAuth/internal/model"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRequireRoles(t *testing.T) {
	tests := []struct {
		name           string
		contextRole    string
		setContextRole bool
		allowedRoles   []model.Role
		expectedStatus int
	}{
		{
			name:           "missing role in context returns 403",
			setContextRole: false,
			allowedRoles:   []model.Role{model.RoleAdmin},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "user role denied when admin required",
			setContextRole: true,
			contextRole:    "USER",
			allowedRoles:   []model.Role{model.RoleAdmin},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "admin role allowed when admin required",
			setContextRole: true,
			contextRole:    "ADMIN",
			allowedRoles:   []model.Role{model.RoleAdmin},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user role allowed when both user and admin allowed",
			setContextRole: true,
			contextRole:    "USER",
			allowedRoles:   []model.Role{model.RoleUser, model.RoleAdmin},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				if tt.setContextRole {
					c.Set("role", tt.contextRole)
				}
				c.Next()
			})
			r.GET("/protected", middleware.RequireRoles(tt.allowedRoles...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
