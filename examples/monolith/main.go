package main

import (
	"log"
	"net/http"
	"time"

	"GoAuth/internal/middleware"
	"GoAuth/internal/model"

	"github.com/gin-gonic/gin"
)

// Example monolithic application showing how to reuse GoAuth middleware
// to protect domain resources (e.g. orders, invoices, accounts).
func main() {
	r := gin.Default()

	// 1. Configure Global Middlewares from GoAuth
	r.Use(middleware.RequestID())
	r.Use(middleware.CORS(middleware.DefaultCORSConfig([]string{"*"})))

	api := r.Group("/api/v1")

	// Public Routes
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "monolith healthy", "time": time.Now().UTC()})
	})

	api.GET("/catalog/products", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"products": []gin.H{
				{"id": "prod_1", "name": "Enterprise Subscription", "price": 499},
				{"id": "prod_2", "name": "Developer Pro License", "price": 99},
			},
		})
	})

	// Protected Routes (Protected with GoAuth AuthMiddleware)
	// Example: authMiddleware.RequireAuth()
	protected := api.Group("/orders")
	// Demonstrate how RBAC role helper works with model.Role:
	roleCheck := middleware.RequireRoles(model.RoleUser, model.RoleAdmin)
	protected.Use(roleCheck)
	{
		// Create a new order (attached to authenticated user)
		protected.POST("", func(c *gin.Context) {
			userID := c.GetString("user_id")
			userEmail := c.GetString("user_email")

			c.JSON(http.StatusCreated, gin.H{
				"order_id":   "ord_987654321",
				"user_id":    userID,
				"user_email": userEmail,
				"status":     "confirmed",
				"total":      499,
			})
		})

		// List orders for the authenticated user
		protected.GET("", func(c *gin.Context) {
			userID := c.GetString("user_id")
			c.JSON(http.StatusOK, gin.H{
				"user_id": userID,
				"orders": []gin.H{
					{"id": "ord_987654321", "total": 499, "status": "confirmed"},
				},
			})
		})
	}

	// Admin-Only Routes (Protected with GoAuth RoleAdmin)
	admin := api.Group("/admin/analytics")
	admin.Use(middleware.RequireRoles(model.RoleAdmin))
	{
		admin.GET("/revenue", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"monthly_recurring_revenue": 125000,
				"active_subscriptions":      412,
			})
		})
	}

	log.Println("Host Monolithic API server configured on :8081")
	_ = r.Run(":8081")
}
