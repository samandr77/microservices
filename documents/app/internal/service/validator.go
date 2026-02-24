package service

import (
	"fmt"

	"github.com/gofrs/uuid/v5"
	"github.com/samandr77/microservices/documents/internal/entity"
)

func ValidateCreateOfertaParams(clientID uuid.UUID, clientName string, oneCguid uuid.UUID) error {
	if clientID.IsNil() || clientName == "" || oneCguid.IsNil() {
		return entity.ErrIncorrectRequestBody
	}

	return nil
}

func ValidateGetDocumentsListParams(clientID uuid.UUID, limit string, ofset string, sortBy string, sortOrder string) error { //nolint:cyclop
	if clientID.IsNil() || limit == "" || ofset == "" || sortBy == "" || sortOrder == "" {
		return fmt.Errorf("%w: clientID: %s, limit: %s, ofset: %s, sortBy: %s, sortOrder: %s",
			entity.ErrIncorrectRequestBody, clientID, limit, ofset, sortBy, sortOrder)
	}

	if sortBy != "name" && sortBy != "doc_type" && sortBy != "created_at" {
		return fmt.Errorf("%w: invalid sortBy param: %s", entity.ErrIncorrectRequestBody, sortBy)
	}

	if sortOrder != "asc" && sortOrder != "desc" {
		return fmt.Errorf("%w: invalid sortOrder param: %s", entity.ErrIncorrectRequestBody, sortOrder)
	}

	return nil
}
