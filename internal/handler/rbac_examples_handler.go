package handler

import (
	"GoAuth/internal/model"

	"github.com/gin-gonic/gin"
)

func AdminOnly(c *gin.Context) {
	c.JSON(200, gin.H{"message": "restricted: admin only"})
}

func UserAdmin(c *gin.Context) {
	c.JSON(200, gin.H{"message": "shared: both user and admin can access this"})
}

func UserDetails(c *gin.Context) {
	currentUserID, _ := c.Get("user_id")
	currentRole, _ := c.Get("role")
	requestedID := c.Param("id")

	// Allow if it's the user themselves OR if the user is an Admin
	if currentUserID != requestedID && currentRole != string(model.RoleAdmin) {
		c.JSON(403, gin.H{"error": "forbidden: only the owner or an admin can access this"})
		return
	}

	c.JSON(200, gin.H{
		"message": "access granted: owner or admin",
		"data":    "sensitive details for user " + requestedID,
	})
}

func UserPrivateDetails(c *gin.Context) {
	currentUserID, _ := c.Get("user_id")
	requestedID := c.Param("id")

	// Strictly only allow the owner. Even Admins are blocked.
	if currentUserID != requestedID {
		c.JSON(403, gin.H{"error": "forbidden: strictly owner only. admins cannot see this"})
		return
	}

	c.JSON(200, gin.H{
		"message": "access granted: strictly owner only",
		"data":    "private vault for user " + requestedID,
	})
}
