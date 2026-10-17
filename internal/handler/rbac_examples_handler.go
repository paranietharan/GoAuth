package handler

import (
	apperrors "GoAuth/internal/errors"
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

	if currentUserID != requestedID && currentRole != string(model.RoleAdmin) {
		apperrors.Write(c, apperrors.ErrForbidden)
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

	if currentUserID != requestedID {
		apperrors.Write(c, apperrors.ErrForbidden)
		return
	}

	c.JSON(200, gin.H{
		"message": "access granted: strictly owner only",
		"data":    "private vault for user " + requestedID,
	})
}
