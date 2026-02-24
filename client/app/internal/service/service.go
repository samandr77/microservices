package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/client/internal/entity"
	"github.com/samandr77/microservices/client/internal/repository"
	"github.com/samandr77/microservices/client/pkg/config"
	"github.com/samandr77/microservices/client/pkg/logger"
)

type AuthClient interface {
	DestroyToken(ctx context.Context, accessToken string) error
	DestroyTokensByUserID(ctx context.Context, userID uuid.UUID) error
}

type Service struct {
	cfg           *config.Config
	userRepo      *repository.UserRepository
	roleRepo      *repository.RoleRepository
	userBlockRepo *repository.UserBlockRepository
	authClient    AuthClient
}

func NewService(
	cfg *config.Config,
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	userBlockRepo *repository.UserBlockRepository,
	authClient AuthClient,
) *Service {
	return &Service{
		cfg:           cfg,
		userRepo:      userRepo,
		roleRepo:      roleRepo,
		userBlockRepo: userBlockRepo,
		authClient:    authClient,
	}
}

func (s *Service) SetUserStatus(ctx context.Context, userID uuid.UUID, status entity.UserStatus) error {
	if !status.IsValid() {
		slog.WarnContext(ctx, "Invalid status for user",
			"user_id", userID, "status", status)
		return entity.ErrInvalidStatus
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for status update",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to set status for non-existent user",
			"user_id", userID, "new_status", status)
		return entity.ErrUserNotFound
	}

	if err := s.validateStatusTransition(user.Status, status); err != nil {
		slog.WarnContext(ctx, "Invalid status transition",
			"user_id", userID, "current_status", user.Status, "new_status", status, "error", err)
		return err
	}

	slog.DebugContext(ctx, "Updating user status",
		"user_id", userID, "old_status", user.Status, "new_status", status)

	err = s.userRepo.UpdateStatus(ctx, userID, status)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to update user status",
			"user_id", userID, "new_status", status, "error", err)
		return err
	}

	slog.InfoContext(ctx, "User status changed successfully",
		"user_id", userID,
		"old_status", user.Status,
		"new_status", status,
	)

	return nil
}

func (s *Service) ActivateUser(ctx context.Context, userID uuid.UUID) error {
	slog.DebugContext(ctx, "Activating user", "user_id", userID)

	err := s.SetUserStatus(ctx, userID, entity.UserStatusActive)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to set user status to active",
			"user_id", userID, "error", err)
		return err
	}

	err = s.userBlockRepo.Delete(ctx, userID)
	if err != nil {
		if !errors.Is(err, entity.ErrBlockNotFound) {
			slog.ErrorContext(ctx, "Failed to delete user block record",
				"user_id", userID, "error", err)
			return err
		}

		slog.DebugContext(ctx, "No user block record to delete",
			"user_id", userID)
	}

	err = s.userRepo.SetDeletedAt(ctx, userID, time.Time{})
	if err != nil {
		slog.ErrorContext(ctx, "Failed to clear deleted_at flag",
			"user_id", userID, "error", err)
		return err
	}

	slog.InfoContext(ctx, "User activated successfully",
		"user_id", userID)

	return nil
}

func (s *Service) BlockUser(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error {
	actingUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return entity.ErrUnauthorized
	}

	if err := s.validateActionPermission(ctx, actingUser.UserID, entity.PermissionBlockUsers); err != nil {
		return err
	}

	currentID := actingUser.UserID

	return s.blockUserWithoutPermission(ctx, userID, blockDuration, "role", &currentID)
}

func (s *Service) BlockUserInternal(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error {
	if blockDuration == nil {
		duration := time.Duration(s.cfg.UserService.TempBlockDurationMinutes) * time.Minute
		blockDuration = &duration
	}

	return s.blockUserWithoutPermission(ctx, userID, blockDuration, "internal", nil)
}

func (s *Service) BlockUserBySecurity(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error {
	return s.blockUserWithoutPermission(ctx, userID, blockDuration, "security", nil)
}

//nolint:funlen
func (s *Service) blockUserWithoutPermission(
	ctx context.Context,
	userID uuid.UUID,
	blockDuration *time.Duration,
	source string,
	actingUser *uuid.UUID,
) error {
	ctx = logger.SetLogType(ctx, "security")

	durationValue := "permanent"
	if blockDuration != nil {
		durationValue = blockDuration.String()
	}

	fields := []any{"user_id", userID, "source", source, "block_duration", durationValue}
	if actingUser != nil {
		fields = append(fields, "acting_user_id", actingUser.String())
	}

	slog.DebugContext(ctx, "Blocking user", fields...)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "error", err)
		slog.ErrorContext(ctx, "Failed to get user for blocking", logFields...)

		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to block non-existent user", fields...)
		return entity.ErrUserNotFound
	}

	if user.Status == entity.UserStatusBlocked {
		slog.WarnContext(ctx, "Attempt to block already blocked user", fields...)
		return entity.ErrUserAlreadyBlocked
	}

	var block *entity.UserBlock
	block, err = s.userBlockRepo.GetByUserID(ctx, userID)

	if err != nil {
		if errors.Is(err, entity.ErrBlockNotFound) {
			block, err = s.createNewUserBlock(ctx, userID, blockDuration)
			if err != nil {
				return err
			}
		} else {
			logFields := append([]any(nil), fields...)
			logFields = append(logFields, "error", err)
			slog.ErrorContext(ctx, "Failed to get user block info", logFields...)

			return err
		}
	} else {
		block, err = s.updateExistingUserBlock(ctx, userID, block, blockDuration)
		if err != nil {
			return err
		}
	}

	if err := s.SetUserStatus(ctx, userID, entity.UserStatusBlocked); err != nil {
		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "error", err)
		slog.ErrorContext(ctx, "Failed to set user status to blocked", logFields...)

		return err
	}

	var tokenDestroyErr error

	if s.authClient != nil {
		if err := s.authClient.DestroyTokensByUserID(ctx, userID); err != nil {
			slog.WarnContext(ctx, "Failed to destroy user tokens, but user marked as blocked",
				"user_id", userID,
				"error", err)

			tokenDestroyErr = entity.ErrTokenDestroyFailed
		}
	} else {
		slog.WarnContext(ctx, "Skipping token destruction: auth client not available", "user_id", userID)
	}

	blockTypeStr := "temporary"
	blocksInPeriod := 0

	if block != nil {
		if block.BlockType != nil && *block.BlockType == entity.BlockTypePermanent {
			blockTypeStr = "permanent"
		}

		blocksInPeriod = block.BlocksByPeriod
	}

	successFields := append([]any(nil), fields...)
	successFields = append(successFields,
		"block_type", blockTypeStr,
		"blocks_in_period", blocksInPeriod,
	)

	slog.ErrorContext(ctx, "User blocked - security event", successFields...)

	return tokenDestroyErr
}

func (s *Service) createNewUserBlock(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) (*entity.UserBlock, error) {
	slog.DebugContext(ctx, "Creating new user block record", "user_id", userID)

	var blockType entity.BlockType
	if blockDuration != nil {
		blockType = entity.BlockTypeTemporary
	} else {
		blockType = entity.BlockTypePermanent
	}

	block := &entity.UserBlock{
		ID:                     uuid.Must(uuid.NewV4()),
		UserID:                 userID,
		BlockType:              &blockType,
		BlocksByPeriod:         1,
		FirstBlockDateByPeriod: &[]time.Time{time.Now()}[0],
	}

	if blockDuration != nil {
		blockedTo := time.Now().Add(*blockDuration)
		block.BlockedTo = &blockedTo
		slog.DebugContext(ctx, "Setting temporary block duration",
			"user_id", userID, "blocked_until", blockedTo)
	} else {
		slog.DebugContext(ctx, "Setting permanent block", "user_id", userID)
	}

	err := s.userBlockRepo.Create(ctx, block)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create user block record",
			"user_id", userID, "error", err)
		return nil, err
	}

	slog.DebugContext(ctx, "User block record created",
		"user_id", userID, "block_id", block.ID)

	return block, nil
}

func (s *Service) updateExistingUserBlock(
	ctx context.Context,
	userID uuid.UUID,
	block *entity.UserBlock,
	blockDuration *time.Duration,
) (*entity.UserBlock, error) {
	slog.DebugContext(ctx, "Processing repeat block for user",
		"user_id", userID, "current_blocks_in_period", block.BlocksByPeriod)

	if block.ShouldResetCounter(s.cfg.UserService.BlockPeriodHours) {
		slog.DebugContext(ctx, "Resetting block counter", "user_id", userID)

		err := s.userBlockRepo.ResetBlockCounter(ctx, userID)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to reset block counter",
				"user_id", userID, "error", err)
			return nil, err
		}

		block.BlocksByPeriod = 0
		block.FirstBlockDateByPeriod = &[]time.Time{time.Now()}[0]
	}

	err := s.userBlockRepo.IncrementBlockCounter(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to increment block counter",
			"user_id", userID, "error", err)
		return nil, err
	}

	block.BlocksByPeriod++

	if block.BlocksByPeriod >= s.cfg.UserService.TempBlocksPerDayLimit {
		ctx = logger.SetLogType(ctx, "security")
		slog.WarnContext(ctx, "User exceeded temporary block limit - converting to permanent block",
			"user_id", userID, "blocks_count", block.BlocksByPeriod, "limit", s.cfg.UserService.TempBlocksPerDayLimit)

		blockType := entity.BlockTypePermanent
		block.BlockType = &blockType
		block.BlockedTo = nil
	} else if blockDuration != nil {
		blockedTo := time.Now().Add(*blockDuration)
		block.BlockedTo = &blockedTo
		slog.DebugContext(ctx, "Setting temporary block duration for repeat block",
			"user_id", userID, "blocked_until", blockedTo)
	}

	err = s.userBlockRepo.Update(ctx, block)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to update user block record",
			"user_id", userID, "error", err)
		return nil, err
	}

	slog.DebugContext(ctx, "User block record updated",
		"user_id", userID, "blocks_count", block.BlocksByPeriod)

	return block, nil
}

func (s *Service) MarkAsDeleted(ctx context.Context, userID uuid.UUID, accessToken string) error {
	currentUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return entity.ErrUnauthorized
	}

	if currentUser.UserID != userID {
		slog.WarnContext(ctx, "Attempt to delete another user's account",
			"current_user_id", currentUser.UserID, "requested_user_id", userID)
		return entity.ErrForbidden
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for deletion",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		return entity.ErrUserNotFound
	}

	if user.Status != entity.UserStatusActive {
		slog.WarnContext(ctx, "Attempt to delete user with non-active status",
			"user_id", userID, "status", user.Status)
		return entity.ErrInvalidStatus
	}

	err = s.SetUserStatus(ctx, userID, entity.UserStatusDeleted)
	if err != nil {
		return err
	}

	err = s.userRepo.SetDeletedAt(ctx, userID, time.Now())
	if err != nil {
		return err
	}

	if s.authClient != nil && accessToken != "" {
		err = s.authClient.DestroyToken(ctx, accessToken)
		if err != nil {
			slog.WarnContext(ctx, "Failed to destroy user token, but user marked as deleted",
				"user_id", userID, "error", err)
		}
	}

	slog.InfoContext(ctx, "User account deletion completed", "user_id", userID)

	return nil
}

func (s *Service) CheckStatusPermissions(ctx context.Context, userID uuid.UUID, action string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return entity.ErrUserNotFound
	}

	if !user.CanPerformAction(action) {
		switch user.Status {
		case entity.UserStatusBlocked:
			return entity.ErrUserBlocked
		case entity.UserStatusDeleted:
			return entity.ErrUserDeleted
		case entity.UserStatusActive:
			return entity.ErrForbidden
		default:
			return entity.ErrForbidden
		}
	}

	if user.Status == entity.UserStatusActive {
		_, err = s.checkUserPermissions(ctx, []string{}, []string{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) ProcessExpiredTemporaryBlocks(ctx context.Context) error {
	blocks, err := s.userBlockRepo.GetExpiredTemporaryBlocks(ctx)
	if err != nil {
		return err
	}

	for _, block := range blocks {
		err = s.ActivateUser(ctx, block.UserID)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to activate user", "user_id", block.UserID, "error", err)
			continue
		}

		slog.InfoContext(ctx, "User automatically unblocked", "user_id", block.UserID)
	}

	return nil
}

func (s *Service) UnblockUser(ctx context.Context, userID uuid.UUID) error {
	actingUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return entity.ErrUnauthorized
	}

	if err := s.validateActionPermission(ctx, actingUser.UserID, entity.PermissionBlockUsers); err != nil {
		return err
	}

	currentID := actingUser.UserID

	return s.unblockUserWithoutPermission(ctx, userID, "role", &currentID)
}

func (s *Service) UnblockUserBySecurity(ctx context.Context, userID uuid.UUID) error {
	return s.unblockUserWithoutPermission(ctx, userID, "security", nil)
}

func (s *Service) unblockUserWithoutPermission(ctx context.Context, userID uuid.UUID, source string, actingUser *uuid.UUID) error {
	fields := []any{"user_id", userID, "source", source}
	if actingUser != nil {
		fields = append(fields, "acting_user_id", actingUser.String())
	}

	slog.DebugContext(ctx, "Attempting to unblock user", fields...)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "error", err)
		slog.ErrorContext(ctx, "Failed to get user for unblock", logFields...)

		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Cannot unblock non-existent user", fields...)
		return entity.ErrUserNotFound
	}

	if user.Status == entity.UserStatusActive {
		slog.WarnContext(ctx, "Cannot unblock already active user", fields...)
		return entity.ErrUserAlreadyActive
	}

	if user.Status != entity.UserStatusBlocked {
		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "status", user.Status)
		slog.WarnContext(ctx, "Cannot unblock non-blocked user", logFields...)

		return entity.ErrInvalidStatus
	}

	block, err := s.userBlockRepo.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, entity.ErrBlockNotFound) {
			slog.DebugContext(ctx, "Block record not found, proceeding with activation", fields...)
			return s.ActivateUser(ctx, userID)
		}

		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "error", err)
		slog.ErrorContext(ctx, "Failed to get user block", logFields...)

		return err
	}

	if block.IsTemporary() {
		logFields := append([]any(nil), fields...)
		logFields = append(logFields, "blocked_to", block.BlockedTo)
		slog.WarnContext(ctx, "Cannot manually unblock temporary block", logFields...)

		return entity.ErrCannotUnblockTemporary
	}

	successFields := append([]any(nil), fields...)
	successFields = append(successFields, "blocks_in_period", block.BlocksByPeriod)
	slog.InfoContext(ctx, "Unblocking permanently blocked user", successFields...)

	return s.ActivateUser(ctx, userID)
}

func (s *Service) RestoreDeletedAccount(ctx context.Context, userID uuid.UUID) error {
	currentUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return entity.ErrUnauthorized
	}

	if currentUser.UserID != userID {
		slog.WarnContext(ctx, "Attempt to restore another user's account",
			"current_user_id", currentUser.UserID, "requested_user_id", userID)
		return entity.ErrForbidden
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user == nil {
		return entity.ErrUserNotFound
	}

	if user.Status != entity.UserStatusDeleted {
		slog.WarnContext(ctx, "Attempt to restore user with non-deleted status",
			"user_id", userID, "status", user.Status)
		return entity.ErrInvalidStatus
	}

	if user.DeletedAt == nil {
		return entity.ErrUserNotFound
	}

	recoveryPeriod := time.Duration(s.cfg.UserService.AccountRecoveryPeriodDays) * config.HoursPerDay * time.Hour
	if time.Since(*user.DeletedAt) > recoveryPeriod {
		return entity.ErrRestorePeriodExpired
	}

	err = s.ActivateUser(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) RestoreUserByID(ctx context.Context, userID uuid.UUID) error {
	slog.DebugContext(ctx, "Restoring deleted account by ID", "user_id", userID)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to find user by ID", "user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "User not found by ID", "user_id", userID)
		return entity.ErrUserNotFound
	}

	if user.Status != entity.UserStatusDeleted {
		slog.WarnContext(ctx, "User account is not deleted", "user_id", userID, "status", user.Status)
		return entity.ErrInvalidStatus
	}

	if user.DeletedAt == nil {
		slog.WarnContext(ctx, "User has no deletion date", "user_id", userID)
		return entity.ErrUserNotFound
	}

	recoveryPeriod := time.Duration(s.cfg.UserService.AccountRecoveryPeriodDays) * config.HoursPerDay * time.Hour
	if time.Since(*user.DeletedAt) > recoveryPeriod {
		slog.WarnContext(ctx, "Restore period expired", "user_id", userID, "deleted_at", user.DeletedAt)
		return entity.ErrRestorePeriodExpired
	}

	err = s.ActivateUser(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to activate user", "user_id", userID, "error", err)
		return err
	}

	slog.InfoContext(ctx, "Successfully restored account by ID", "user_id", userID)

	return nil
}

func (s *Service) CleanupExpiredDeletedAccounts(ctx context.Context) error {
	slog.DebugContext(ctx, "Starting cleanup of expired deleted accounts")

	recoveryPeriod := time.Duration(s.cfg.UserService.AccountRecoveryPeriodDays) * config.HoursPerDay * time.Hour
	expirationDate := time.Now().Add(-recoveryPeriod)

	slog.DebugContext(ctx, "Calculating expiration threshold",
		"recovery_period_days", s.cfg.UserService.AccountRecoveryPeriodDays,
		"expiration_date", expirationDate)

	userIDs, err := s.userRepo.GetExpiredDeletedAccounts(ctx, expirationDate)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get expired deleted accounts", "error", err)
		return err
	}

	if len(userIDs) == 0 {
		slog.DebugContext(ctx, "No expired deleted accounts found")
		return nil
	}

	slog.InfoContext(ctx, "Found expired deleted accounts", "count", len(userIDs))

	var failedDeletes int

	for _, userID := range userIDs {
		err := s.userRepo.PermanentlyDelete(ctx, userID)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to permanently delete user",
				"user_id", userID, "error", err)

			failedDeletes++

			continue
		}

		slog.InfoContext(ctx, "User permanently deleted",
			"user_id", userID)
	}

	if failedDeletes > 0 {
		slog.WarnContext(ctx, "Cleanup completed with errors",
			"total_accounts", len(userIDs),
			"failed_deletes", failedDeletes,
			"successful_deletes", len(userIDs)-failedDeletes)
	} else {
		slog.InfoContext(ctx, "Cleanup completed successfully",
			"total_accounts_deleted", len(userIDs))
	}

	return nil
}

func (s *Service) checkUserPermissions(_ context.Context, _ []string, _ []string) (*entity.User, error) {
	return nil, entity.ErrForbidden
}

func (s *Service) validateStatusTransition(currentStatus, newStatus entity.UserStatus) error {
	switch currentStatus {
	case entity.UserStatusActive:
		if newStatus == entity.UserStatusBlocked || newStatus == entity.UserStatusDeleted {
			return nil
		}
	case entity.UserStatusBlocked:
		if newStatus == entity.UserStatusActive || newStatus == entity.UserStatusDeleted {
			return nil
		}
	case entity.UserStatusDeleted:
		if newStatus == entity.UserStatusActive {
			return nil
		}
	}

	return entity.ErrCannotChangeStatus
}

func (s *Service) CreateUserByEmail(
	ctx context.Context,
	email, firstName, lastName string,
	privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
) (uuid.UUID, error) {
	if err := ValidateEmail(email); err != nil {
		slog.WarnContext(ctx, "Invalid email format for user creation",
			"email", email, "error", err)
		return uuid.Nil, err
	}

	if err := ValidateName(&firstName, "first_name", true); err != nil {
		slog.WarnContext(ctx, "Invalid first_name for user creation",
			"error", err)
		return uuid.Nil, err
	}

	if err := ValidateName(&lastName, "last_name", true); err != nil {
		slog.WarnContext(ctx, "Invalid last_name for user creation",
			"error", err)
		return uuid.Nil, err
	}

	if !privacyPolicyAgreed {
		slog.WarnContext(ctx, "Privacy policy agreement required for user creation",
			"email", email)
		return uuid.Nil, entity.ErrPrivacyPolicyRequired
	}

	hasDuplicates, err := s.userRepo.CheckDuplicates(ctx, &email, nil, nil)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to check duplicates",
			"email", email, "error", err)
		return uuid.Nil, err
	}

	if hasDuplicates {
		slog.WarnContext(ctx, "Attempt to create user with duplicate email",
			"email", email)
		return uuid.Nil, entity.ErrDuplicateEmail
	}

	donorRole, err := s.roleRepo.GetByName(ctx, entity.RoleDonor)
	if err != nil {
		return uuid.Nil, err
	}

	user := &entity.User{
		Email:                 email,
		FirstName:             &firstName,
		LastName:              &lastName,
		RoleID:                donorRole.ID,
		Status:                entity.UserStatusActive,
		VerificationStatus:    entity.VerificationStatusUnverified,
		PrivacyPolicyAgreed:   privacyPolicyAgreed,
		NewsletterAgreed:      newsletterAgreed,
		PublicDonationsAgreed: publicDonationsAgreed,
	}

	userID, err := s.userRepo.Create(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create user in database",
			"email", email, "error", err)
		return uuid.Nil, err
	}

	slog.InfoContext(ctx, "User created by email",
		"user_id", userID,
		"email", email,
	)

	return userID, nil
}

func (s *Service) CreateUserBySberID(ctx context.Context, sberData *SberIDData) (uuid.UUID, error) {
	if sberData.Email == nil {
		slog.WarnContext(ctx, "Email is required for Sber ID user creation")
		return uuid.Nil, entity.ErrMissingRequiredField
	}

	email := *sberData.Email

	if err := ValidateEmail(email); err != nil {
		slog.WarnContext(ctx, "Invalid email in Sber ID data",
			"email", email, "error", err)
		return uuid.Nil, err
	}

	if err := ValidateName(sberData.FirstName, "first_name", true); err != nil {
		slog.WarnContext(ctx, "Invalid first_name in Sber ID data",
			"error", err)
		return uuid.Nil, err
	}

	if err := ValidateName(sberData.LastName, "last_name", true); err != nil {
		slog.WarnContext(ctx, "Invalid last_name in Sber ID data",
			"error", err)
		return uuid.Nil, err
	}

	if err := ValidateName(sberData.MiddleName, "middle_name", false); err != nil {
		slog.WarnContext(ctx, "Invalid middle_name in Sber ID data",
			"error", err)
		return uuid.Nil, err
	}

	if err := ValidatePhone(sberData.Phone); err != nil {
		slog.WarnContext(ctx, "Invalid phone in Sber ID data",
			"error", err)
		return uuid.Nil, err
	}

	if !sberData.PrivacyPolicyAgreed {
		slog.WarnContext(ctx, "Privacy policy agreement required for user creation",
			"email", email)
		return uuid.Nil, entity.ErrPrivacyPolicyRequired
	}

	hasDuplicates, err := s.userRepo.CheckDuplicates(ctx, sberData.Email, sberData.Sub, sberData.SubAlt)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to check duplicates for Sber ID",
			"email", email, "sub", sberData.Sub, "error", err)
		return uuid.Nil, err
	}

	if hasDuplicates {
		slog.WarnContext(ctx, "Attempt to create user with duplicate email or sub/sub_alt",
			"email", email, "sub", sberData.Sub, "sub_alt", sberData.SubAlt)
		return uuid.Nil, entity.ErrDuplicateEmail
	}

	donorRole, err := s.roleRepo.GetByName(ctx, entity.RoleDonor)
	if err != nil {
		return uuid.Nil, err
	}

	user := &entity.User{
		Sub:                   sberData.Sub,
		SubAlt:                sberData.SubAlt,
		Email:                 email,
		Phone:                 sberData.Phone,
		LastName:              sberData.LastName,
		FirstName:             sberData.FirstName,
		MiddleName:            sberData.MiddleName,
		Birthdate:             sberData.Birthdate,
		RoleID:                donorRole.ID,
		Status:                entity.UserStatusActive,
		VerificationStatus:    entity.VerificationStatusUnverified,
		PrivacyPolicyAgreed:   sberData.PrivacyPolicyAgreed,
		NewsletterAgreed:      sberData.NewsletterAgreed,
		PublicDonationsAgreed: sberData.PublicDonationsAgreed,
	}

	userID, err := s.userRepo.Create(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create Sber ID user in database",
			"email", email, "sub", sberData.Sub, "error", err)
		return uuid.Nil, err
	}

	slog.InfoContext(ctx, "User created by Sber ID",
		"user_id", userID,
		"email", email,
		"sub", sberData.Sub,
	)

	return userID, nil
}

func (s *Service) MergeUserData(ctx context.Context, userID uuid.UUID, sberData *SberIDData) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for merge",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to merge data for non-existent user",
			"user_id", userID)
		return entity.ErrUserNotFound
	}

	if err := ValidatePhone(sberData.Phone); err != nil {
		slog.WarnContext(ctx, "Invalid phone in merge data",
			"user_id", userID, "error", err)
		return err
	}

	fields := make(map[string]any)

	if user.Sub == nil && sberData.Sub != nil {
		fields["sub"] = sberData.Sub
	}

	if user.SubAlt == nil && sberData.SubAlt != nil {
		fields["sub_alt"] = sberData.SubAlt
	}

	if user.Phone == nil && sberData.Phone != nil {
		fields["phone"] = sberData.Phone
	}

	if user.LastName == nil && sberData.LastName != nil {
		fields["last_name"] = sberData.LastName
	}

	if user.FirstName == nil && sberData.FirstName != nil {
		fields["first_name"] = sberData.FirstName
	}

	if user.MiddleName == nil && sberData.MiddleName != nil {
		fields["middle_name"] = sberData.MiddleName
	}

	if user.Birthdate == nil && sberData.Birthdate != nil {
		fields["birthdate"] = sberData.Birthdate
	}

	if len(fields) > 0 {
		slog.DebugContext(ctx, "Merging user data",
			"user_id", userID, "fields_count", len(fields))

		err = s.userRepo.PartialUpdate(ctx, userID, fields)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to merge user data",
				"user_id", userID, "fields_count", len(fields), "error", err)
			return err
		}

		slog.InfoContext(ctx, "User data merged successfully",
			"user_id", userID,
			"fields_count", len(fields),
		)
	} else {
		slog.DebugContext(ctx, "No new fields to merge for user",
			"user_id", userID)
	}

	return nil
}

//nolint:funlen
func (s *Service) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileData *ProfileUpdateData) error {
	currentUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return entity.ErrUnauthorized
	}

	if currentUser.UserID != userID {
		slog.WarnContext(ctx, "Attempt to update another user's profile",
			"current_user_id", currentUser.UserID, "requested_user_id", userID)
		return entity.ErrForbidden
	}

	err = s.validateActionPermission(ctx, currentUser.UserID, entity.PermissionEditProfile)
	if err != nil {
		return err
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for profile update",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to update profile for non-existent user",
			"user_id", userID)
		return entity.ErrUserNotFound
	}

	fields := make(map[string]any)

	if profileData.LastName != nil {
		fields["last_name"] = profileData.LastName
	}

	if profileData.FirstName != nil {
		fields["first_name"] = profileData.FirstName
	}

	if profileData.MiddleName != nil {
		fields["middle_name"] = profileData.MiddleName
	}

	if profileData.Phone != nil {
		fields["phone"] = profileData.Phone
	}

	if profileData.Birthdate != nil {
		fields["birthdate"] = profileData.Birthdate
	}

	if profileData.City != nil {
		fields["city"] = profileData.City
	}

	if profileData.SchoolName != nil {
		fields["school_name"] = profileData.SchoolName
	}

	if profileData.PlaceOfEducation != nil {
		fields["place_of_education"] = profileData.PlaceOfEducation
	}

	if profileData.AddressReg != nil {
		fields["address_reg"] = profileData.AddressReg
	}

	if profileData.Series != nil {
		fields["series"] = profileData.Series
	}

	if profileData.Number != nil {
		fields["number"] = profileData.Number
	}

	if profileData.IssuedBy != nil {
		fields["issued_by"] = profileData.IssuedBy
	}

	if profileData.IssuedDate != nil {
		fields["issued_date"] = profileData.IssuedDate
	}

	if profileData.Code != nil {
		fields["code"] = profileData.Code
	}

	if profileData.PersonalInfo != nil {
		fields["personal_info"] = profileData.PersonalInfo
	}

	if len(fields) > 0 {
		slog.DebugContext(ctx, "Updating user profile",
			"user_id", userID, "fields_count", len(fields))

		err = s.userRepo.PartialUpdate(ctx, userID, fields)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to update user profile",
				"user_id", userID, "fields_count", len(fields), "error", err)
			return err
		}

		slog.InfoContext(ctx, "User profile updated successfully",
			"user_id", userID,
			"fields_count", len(fields),
		)
	} else {
		slog.DebugContext(ctx, "No fields provided for profile update",
			"user_id", userID)
	}

	return nil
}

func (s *Service) UpdateUserProfileInternal(ctx context.Context, userID uuid.UUID, profileData *ProfileUpdateData) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for profile update",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to update profile for non-existent user",
			"user_id", userID)
		return entity.ErrUserNotFound
	}

	fields := make(map[string]any)

	if profileData.LastName != nil {
		fields["last_name"] = profileData.LastName
	}

	if profileData.FirstName != nil {
		fields["first_name"] = profileData.FirstName
	}

	if profileData.MiddleName != nil {
		fields["middle_name"] = profileData.MiddleName
	}

	if profileData.Phone != nil {
		fields["phone"] = profileData.Phone
	}

	if profileData.Birthdate != nil {
		fields["birthdate"] = profileData.Birthdate
	}

	if profileData.City != nil {
		fields["city"] = profileData.City
	}

	if profileData.SchoolName != nil {
		fields["school_name"] = profileData.SchoolName
	}

	if profileData.PlaceOfEducation != nil {
		fields["place_of_education"] = profileData.PlaceOfEducation
	}

	if profileData.AddressReg != nil {
		fields["address_reg"] = profileData.AddressReg
	}

	if profileData.Series != nil {
		fields["series"] = profileData.Series
	}

	if profileData.Number != nil {
		fields["number"] = profileData.Number
	}

	if profileData.IssuedBy != nil {
		fields["issued_by"] = profileData.IssuedBy
	}

	if profileData.IssuedDate != nil {
		fields["issued_date"] = profileData.IssuedDate
	}

	if profileData.Code != nil {
		fields["code"] = profileData.Code
	}

	if profileData.PersonalInfo != nil {
		fields["personal_info"] = profileData.PersonalInfo
	}

	if len(fields) > 0 {
		slog.DebugContext(ctx, "Updating user profile (internal)",
			"user_id", userID, "fields_count", len(fields))

		err = s.userRepo.PartialUpdate(ctx, userID, fields)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to update user profile",
				"user_id", userID, "fields_count", len(fields), "error", err)
			return err
		}

		slog.InfoContext(ctx, "User profile updated successfully (internal)",
			"user_id", userID,
			"fields_count", len(fields),
		)
	} else {
		slog.DebugContext(ctx, "No fields provided for profile update",
			"user_id", userID)
	}

	return nil
}

func (s *Service) UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	if err := ValidateEmail(newEmail); err != nil {
		slog.WarnContext(ctx, "Invalid email format for update",
			"user_id", userID, "new_email", newEmail, "error", err)
		return err
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for email update",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to update email for non-existent user",
			"user_id", userID)
		return entity.ErrUserNotFound
	}

	if user.Email == newEmail {
		slog.DebugContext(ctx, "New email is the same as current email, no update needed",
			"user_id", userID, "email", newEmail)
		return nil
	}

	slog.DebugContext(ctx, "Updating user email",
		"user_id", userID, "old_email", user.Email, "new_email", newEmail)

	fields := map[string]interface{}{
		"email": newEmail,
	}

	err = s.userRepo.PartialUpdate(ctx, userID, fields)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to update user email",
			"user_id", userID, "new_email", newEmail, "error", err)
		return err
	}

	slog.InfoContext(ctx, "User email updated successfully",
		"user_id", userID,
		"old_email", user.Email,
		"new_email", newEmail,
	)

	return nil
}

func (s *Service) FindUserByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	slog.DebugContext(ctx, "Finding user by email", "email", email)

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		slog.DebugContext(ctx, "User not found by email", "email", email, "error", err)
		return uuid.Nil, err
	}

	if user == nil {
		slog.DebugContext(ctx, "User is nil for email", "email", email)
		return uuid.Nil, entity.ErrUserNotFound
	}

	slog.DebugContext(ctx, "User found by email",
		"user_id", user.UserID, "email", email)

	return user.UserID, nil
}

func (s *Service) SearchUser(ctx context.Context, email, sub, subAlt *string) (*entity.User, error) {
	var (
		user *entity.User
		err  error
	)

	switch {
	case email != nil && *email != "":
		slog.DebugContext(ctx, "Searching user by email", "email", *email)
		user, err = s.userRepo.GetByEmail(ctx, *email)
	case sub != nil && *sub != "":
		slog.DebugContext(ctx, "Searching user by sub", "sub", *sub)
		user, err = s.userRepo.GetBySub(ctx, *sub)
	case subAlt != nil && *subAlt != "":
		slog.DebugContext(ctx, "Searching user by sub_alt", "sub_alt", *subAlt)
		user, err = s.userRepo.GetBySubAlt(ctx, *subAlt)
	default:
		slog.WarnContext(ctx, "SearchUser called without any valid parameters",
			"email", email, "sub", sub, "subAlt", subAlt)
		return nil, entity.ErrValidationFailed
	}

	if err != nil {
		return nil, err
	}

	if user.Status == entity.UserStatusDeleted {
		slog.WarnContext(ctx, "Attempt to access deleted user", "user_id", user.UserID)

		return nil, entity.ErrUserDeleted
	}

	if user.Status == entity.UserStatusBlocked {
		slog.WarnContext(ctx, "Attempt to access blocked user", "user_id", user.UserID)

		return nil, entity.ErrUserBlocked
	}

	slog.InfoContext(ctx, "User found by filter search",
		"user_id", user.UserID,
		"status", user.Status,
	)

	return user, nil
}

func (s *Service) GetUserProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	currentUser, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get current user from context", "error", err)
		return nil, entity.ErrUnauthorized
	}

	if currentUser.UserID != userID {
		slog.WarnContext(ctx, "Attempt to view another user's profile",
			"current_user_id", currentUser.UserID, "requested_user_id", userID)
		return nil, entity.ErrForbidden
	}

	err = s.validateActionPermission(ctx, currentUser.UserID, entity.PermissionViewProfile)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user profile from database", "user_id", userID, "error", err)
		return nil, err
	}

	if user.Status == entity.UserStatusBlocked {
		slog.WarnContext(ctx, "Attempt to access blocked user profile", "user_id", user.UserID)
		return nil, entity.ErrUserBlocked
	}

	return user, nil
}

func (s *Service) GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	slog.DebugContext(ctx, "Getting user by ID (internal)", "user_id", userID)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user by ID", "user_id", userID, "error", err)
		return nil, err
	}

	if user == nil {
		slog.WarnContext(ctx, "User not found by ID", "user_id", userID)
		return nil, entity.ErrUserNotFound
	}

	slog.DebugContext(ctx, "User retrieved by ID", "user_id", userID, "status", user.Status)

	return user, nil
}

func (s *Service) CheckUserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, entity.ErrUserNotFound) {
			slog.DebugContext(ctx, "User existence check: not found", "user_id", userID)
			return false, nil
		}

		return false, err
	}

	if user == nil || user.DeletedAt != nil {
		return false, nil
	}

	slog.DebugContext(ctx, "User existence check: exists",
		"user_id", userID,
		"status", user.Status,
	)

	return true, nil
}

func (s *Service) GetUserBlock(ctx context.Context, userID uuid.UUID) (*entity.UserBlock, error) {
	return s.userBlockRepo.GetByUserID(ctx, userID)
}

func (s *Service) GetDefaultRole(ctx context.Context) (uuid.UUID, error) {
	slog.DebugContext(ctx, "Getting default donor role")

	role, err := s.roleRepo.GetByName(ctx, entity.RoleDonor)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get default donor role", "error", err)
		return uuid.Nil, err
	}

	if role == nil {
		slog.ErrorContext(ctx, "Default donor role not found")
		return uuid.Nil, errors.New("default donor role not found")
	}

	slog.DebugContext(ctx, "Default donor role retrieved", "role_id", role.ID)

	return role.ID, nil
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	slog.DebugContext(ctx, "Assigning role to user", "user_id", userID, "role_id", roleID)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for role assignment",
			"user_id", userID, "error", err)
		return err
	}

	if user == nil {
		slog.WarnContext(ctx, "Attempt to assign role to non-existent user",
			"user_id", userID)
		return entity.ErrUserNotFound
	}

	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get role for assignment",
			"role_id", roleID, "error", err)
		return err
	}

	if role == nil {
		slog.WarnContext(ctx, "Attempt to assign non-existent role",
			"role_id", roleID)
		return errors.New("role not found")
	}

	err = s.userRepo.PartialUpdate(ctx, userID, map[string]interface{}{
		"role_id": roleID,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Failed to update user role",
			"user_id", userID, "role_id", roleID, "error", err)
		return err
	}

	slog.InfoContext(ctx, "Role assigned to user successfully",
		"user_id", userID, "role_id", roleID, "role_name", role.Name)

	return nil
}

func (s *Service) GetUserRole(ctx context.Context, userID uuid.UUID) (*entity.Role, error) {
	slog.DebugContext(ctx, "Getting user role", "user_id", userID)

	role, err := s.roleRepo.GetRoleByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user role",
			"user_id", userID, "error", err)
		return nil, err
	}

	if role == nil {
		slog.WarnContext(ctx, "User role not found", "user_id", userID)
		return nil, errors.New("user role not found")
	}

	slog.DebugContext(ctx, "User role retrieved",
		"user_id", userID, "role_id", role.ID, "role_name", role.Name)

	return role, nil
}

func (s *Service) ListAllRoles(ctx context.Context) ([]*entity.Role, error) {
	slog.DebugContext(ctx, "Listing all roles")

	roles, err := s.roleRepo.GetAll(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to list all roles", "error", err)
		return nil, err
	}

	slog.DebugContext(ctx, "All roles retrieved", "roles_count", len(roles))

	return roles, nil
}

type SberIDData struct {
	Sub                   *string `json:"sub"`
	SubAlt                *string `json:"sub_alt"`
	Email                 *string `json:"email"`
	Phone                 *string `json:"phone"`
	LastName              *string `json:"last_name"`
	FirstName             *string `json:"first_name"`
	MiddleName            *string `json:"middle_name"`
	Birthdate             *string `json:"birthdate"`
	PrivacyPolicyAgreed   bool    `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool    `json:"newsletter_agreed"`
	PublicDonationsAgreed bool    `json:"public_donations_agreed"`
}

type ProfileUpdateData struct {
	LastName   *string `json:"last_name"`
	FirstName  *string `json:"first_name"`
	MiddleName *string `json:"middle_name"`

	Phone     *string `json:"phone"`
	Birthdate *string `json:"birthdate"`

	City             *string `json:"city"`
	SchoolName       *string `json:"school_name"`
	PlaceOfEducation *string `json:"place_of_education"`
	AddressReg       *string `json:"address_reg"`

	Series       *string `json:"series"`
	Number       *string `json:"number"`
	IssuedBy     *string `json:"issued_by"`
	IssuedDate   *string `json:"issued_date"`
	Code         *string `json:"code"`
	PersonalInfo *string `json:"personal_info"`
}

func (s *Service) ValidateUserPermission(ctx context.Context, userID uuid.UUID, permission string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for permission check",
			"user_id", userID, "permission", permission, "error", err)
		return err
	}

	if user == nil {
		return entity.ErrUserNotFound
	}

	if user.Status != entity.UserStatusActive {
		slog.WarnContext(ctx, "User cannot perform action: not active",
			"user_id", userID, "status", user.Status, "permission", permission)

		switch user.Status {
		case entity.UserStatusActive:
			return nil
		case entity.UserStatusBlocked:
			return entity.ErrUserBlocked
		case entity.UserStatusDeleted:
			return entity.ErrUserDeleted
		default:
			return entity.ErrForbidden
		}
	}

	role, err := s.roleRepo.GetRoleByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user role for permission check",
			"user_id", userID, "permission", permission, "error", err)
		return err
	}

	if !entity.HasPermission(role.Name, permission) {
		slog.WarnContext(ctx, "Permission denied",
			"user_id", userID, "role", role.Name, "permission", permission)
		return entity.ErrPermissionDenied
	}

	return nil
}

func (s *Service) validateActionPermission(ctx context.Context, userID uuid.UUID, permission string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user for permission check",
			"user_id", userID, "permission", permission, "error", err)
		return err
	}

	if user == nil {
		return entity.ErrUserNotFound
	}

	if user.Status != entity.UserStatusActive {
		slog.WarnContext(ctx, "User cannot perform action: not active",
			"user_id", userID, "status", user.Status, "permission", permission)

		switch user.Status {
		case entity.UserStatusActive:
			return entity.ErrForbidden
		case entity.UserStatusBlocked:
			return entity.ErrUserBlocked
		case entity.UserStatusDeleted:
			return entity.ErrUserDeleted
		default:
			return entity.ErrForbidden
		}
	}

	role, err := s.roleRepo.GetRoleByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get user role for permission check",
			"user_id", userID, "permission", permission, "error", err)
		return err
	}

	if !entity.HasPermission(role.Name, permission) {
		slog.WarnContext(ctx, "Permission denied",
			"user_id", userID, "role", role.Name, "permission", permission)
		return entity.ErrPermissionDenied
	}

	slog.DebugContext(ctx, "Permission check passed",
		"user_id", userID, "role", role.Name, "permission", permission)

	return nil
}
