package errors

type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
	Cause      error  `json:"-"`
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func New(code, message string, status int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: status}
}

func Wrap(code, message string, status int, cause error) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: status, Cause: cause}
}
