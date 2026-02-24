package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/client/internal/service"
)

func parseSearchUserParams(q url.Values) (email, sub, subAlt *string, err error) {
	emailVal := q.Get("email")
	subVal := q.Get("sub")
	subAltVal := q.Get("sub_alt")

	paramCount := 0
	if emailVal != "" {
		paramCount++
	}

	if subVal != "" {
		paramCount++
	}

	if subAltVal != "" {
		paramCount++
	}

	if paramCount != 1 {
		return nil, nil, nil, errors.New("must specify exactly one parameter: email, sub, or sub_alt")
	}

	if subVal != "" && len(subVal) > service.SberIDMaxLen {
		return nil, nil, nil, fmt.Errorf("sub превышает максимально допустимую длину %d символов", service.SberIDMaxLen)
	}

	if subAltVal != "" && len(subAltVal) > service.SberIDMaxLen {
		return nil, nil, nil, fmt.Errorf("sub_alt превышает максимально допустимую длину %d символов", service.SberIDMaxLen)
	}

	var emailPtr, subPtr, subAltPtr *string

	if emailVal != "" {
		emailPtr = &emailVal
	}

	if subVal != "" {
		subPtr = &subVal
	}

	if subAltVal != "" {
		subAltPtr = &subAltVal
	}

	return emailPtr, subPtr, subAltPtr, nil
}

func parseGetUserParams(userIDStr string) (userID uuid.UUID, err error) {
	if userIDStr == "" {
		return uuid.Nil, errors.New("user_id is required")
	}

	userID, err = uuid.FromString(userIDStr)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

type ResponseError struct {
	Message string `json:"message"`
}

func sendErr(_ context.Context, w http.ResponseWriter, code int, _ error, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(ResponseError{Message: msg}); err != nil {
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}

func sendJSON(_ context.Context, w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func getValidationMessage(err error) string {
	msg := err.Error()
	if idx := strings.Index(msg, ": "); idx != -1 {
		return msg[idx+2:]
	}

	return msg
}

func parseUserIDFromRequest(r *http.Request) (uuid.UUID, error) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return uuid.Nil, err
	}

	return uuid.FromString(req.UserID)
}

func extractTokenFromHeader(r *http.Request) string {
	const bearerParts = 2

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", bearerParts)
	if len(parts) != bearerParts || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}
