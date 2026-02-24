package entity

import (
	"github.com/gofrs/uuid/v5"
)

type Role struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"role_name"`
}

const (
	RoleDonor           = "donor"
	RoleBoardMember     = "board_member"
	RoleNPO             = "npo"
	RoleContentManager  = "content_manager"
	RoleClientManager   = "client_manager"
	RoleSupportEmployee = "support_employee"
	RoleTechnicalAdmin  = "technical_admin"
	RoleBusinessAdmin   = "business_admin"
)
