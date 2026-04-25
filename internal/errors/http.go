package errors

import "github.com/gin-gonic/gin"

type errorEnvelope struct {
	Error *AppError `json:"error"`
}

func Write(c *gin.Context, err *AppError) {
	if err == nil {
		err = ErrInternal
	}
	c.AbortWithStatusJSON(err.HTTPStatus, errorEnvelope{Error: &AppError{Code: err.Code, Message: err.Message}})
}
