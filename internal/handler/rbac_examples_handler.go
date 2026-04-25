package handler

import "github.com/gin-gonic/gin"

func AdminOnly(c *gin.Context) {
	c.JSON(200, gin.H{"message": "admin access granted"})
}
