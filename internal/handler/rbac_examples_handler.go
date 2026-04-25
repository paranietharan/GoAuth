package handler

import "github.com/gin-gonic/gin"

func AdminOnly(c *gin.Context) {
	c.JSON(200, gin.H{"message": "admin access granted"})
}

func OwnerOnly(c *gin.Context) {
	c.JSON(200, gin.H{"message": "owner access granted"})
}

func AdminOwner(c *gin.Context) {
	c.JSON(200, gin.H{"message": "admin or owner access granted"})
}
