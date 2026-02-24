package entity

const (
	PermissionViewProfile         = "view_profile"
	PermissionEditProfile         = "edit_profile"
	PermissionManageUsers         = "manage_users"
	PermissionBlockUsers          = "block_users"
	PermissionDeleteUsers         = "delete_users"
	PermissionManageRoles         = "manage_roles"
	PermissionManageContent       = "manage_content"
	PermissionManageNPO           = "manage_npo"
	PermissionAccessBoardMeetings = "access_board_meetings"
	PermissionViewClosedInfo      = "view_closed_info"
	PermissionFinancialSupport    = "financial_support"
	PermissionViewAllData         = "view_all_data"
)

func GetPermissionsByRole(roleName string) []string {
	rolePermissions := map[string][]string{
		RoleDonor: {
			PermissionViewProfile,
			PermissionEditProfile,
		},
		RoleBoardMember: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionAccessBoardMeetings,
			PermissionViewClosedInfo,
		},
		RoleNPO: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionManageNPO,
		},
		RoleContentManager: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionManageContent,
		},
		RoleClientManager: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionManageNPO,
			PermissionManageUsers,
		},
		RoleSupportEmployee: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionFinancialSupport,
		},
		RoleTechnicalAdmin: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionManageUsers,
			PermissionBlockUsers,
			PermissionManageRoles,
		},
		RoleBusinessAdmin: {
			PermissionViewProfile,
			PermissionEditProfile,
			PermissionManageUsers,
			PermissionBlockUsers,
			PermissionDeleteUsers,
			PermissionManageRoles,
			PermissionManageContent,
			PermissionManageNPO,
			PermissionViewAllData,
			PermissionFinancialSupport,
		},
	}

	permissions, exists := rolePermissions[roleName]
	if !exists {
		return []string{PermissionViewProfile}
	}

	return permissions
}

func HasPermission(roleName, permission string) bool {
	permissions := GetPermissionsByRole(roleName)
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}
