package errors

import (
	"errors"
	"fmt"
	"net/http"
)

type AppError struct {
	Code     string         `json:"code"`
	Status   int            `json:"-"`
	Message  string         `json:"message"`
	Hint     string         `json:"hint,omitempty"`
	Field    string         `json:"field,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	Internal error          `json:"-"`
}

func (e *AppError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Internal
}

func (e *AppError) WithInternal(err error) *AppError {
	e.Internal = err
	return e
}

func (e *AppError) WithField(field string) *AppError {
	e.Field = field
	return e
}

func (e *AppError) WithDetail(key string, value any) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]any)
	}
	e.Details[key] = value
	return e
}

func ErrInternal(err error) *AppError {
	return &AppError{
		Code:     CodeInternal,
		Status:   http.StatusInternalServerError,
		Message:  "An unexpected error occurred",
		Internal: err,
	}
}

func ErrNotFound(entity string, id any) *AppError {
	return &AppError{
		Code:    CodeNotFound,
		Status:  http.StatusNotFound,
		Message: fmt.Sprintf("%s with ID %v not found", entity, id),
	}
}

func ErrUnauthorized() *AppError {
	return &AppError{
		Code:    CodeUnauthorized,
		Status:  http.StatusUnauthorized,
		Message: "Authentication required",
		Hint:    "Provide a valid API key in X-WAF-Admin-Key header",
	}
}

func ErrForbidden(reason string) *AppError {
	return &AppError{
		Code:    CodeForbidden,
		Status:  http.StatusForbidden,
		Message: "Access denied",
		Hint:    reason,
	}
}

func ErrValidation(field, msg string) *AppError {
	return &AppError{
		Code:    CodeValidation,
		Status:  http.StatusBadRequest,
		Message: msg,
		Field:   field,
	}
}

func FromError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return ErrInternal(err)
}
