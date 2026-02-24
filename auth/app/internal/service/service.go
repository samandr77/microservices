package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/samandr77/microservices/auth/internal/clients/sberid"
	"github.com/samandr77/microservices/auth/internal/clients/users"
	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/pkg/config"
	"github.com/samandr77/microservices/auth/pkg/logger"
)

const (
	maxCodeValue = 1000000
)

type CodeRepository interface {
	SaveVerificationCode(ctx context.Context, code entity.VerificationCode) error
	FindByEmailAndAction(ctx context.Context, email string, action entity.VerificationAction) (entity.VerificationCode, error)
	MarkAsUsed(ctx context.Context, codeID uuid.UUID) error
	CountByEmailAndAction(ctx context.Context, email string, action entity.VerificationAction, since time.Time) (int, error)
	DeleteCode(ctx context.Context, codeID uuid.UUID) error
	DeleteByEmail(ctx context.Context, email string) error
	DeleteExpiredCode(ctx context.Context) error
	DeleteUsedCodes(ctx context.Context) error
}

type RefreshTokenRepository interface {
	SaveRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error
	FindRefreshToken(ctx context.Context, token string) error
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	CleanExpired(ctx context.Context) error
	GetActiveRefreshTokensByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type AttemptRepository interface {
	SaveAttempt(ctx context.Context, attempt entity.Attempt) error
	CountByEmailAndType(ctx context.Context, email string, attemptType entity.AttemptType, since time.Time) (int, error)
	CountByIPAndType(ctx context.Context, ipAddress string, attemptType entity.AttemptType, since time.Time) (int, error)
	GetLastAttemptByEmail(ctx context.Context, email string, attemptType entity.AttemptType) (entity.Attempt, error)
	GetLastAttemptByIP(ctx context.Context, ipAddress string, attemptType entity.AttemptType) (entity.Attempt, error)
	GetLastBlockByEmail(ctx context.Context, email string, attemptType string) (entity.AttemptBlock, error)
	GetLastBlockByIP(ctx context.Context, ipAddress string, attemptType string) (entity.AttemptBlock, error)
	LastAttemptBlockByIP(ctx context.Context, ipAddress string, attemptType entity.AttemptType) (entity.AttemptBlock, error)
	AttemptsByIP(ctx context.Context, ipAddress string, attemptType entity.AttemptType, createdAt time.Time) ([]entity.Attempt, error)
	AttemptsByEmailAndIP(
		ctx context.Context,
		email string,
		ipAddress string,
		attemptType entity.AttemptType,
		since time.Time,
	) ([]entity.Attempt, error)
	SendAttemptsByEmailAndIP(
		ctx context.Context,
		email string,
		ipAddress string,
		attemptType entity.AttemptType,
		since time.Time,
	) ([]entity.Attempt, error)
	CheckAttemptsByEmailAndIP(
		ctx context.Context,
		email string,
		ipAddress string,
		attemptType entity.AttemptType,
		since time.Time,
	) ([]entity.Attempt, error)
	AddAttemptBlocks(ctx context.Context, attemptBlocks entity.AttemptBlock) error
	CleanExpiredBlocks(ctx context.Context) error
}

type NotificationService interface {
	SendEmailVerificationCode(ctx context.Context, email, code string)
}

type Service struct {
	cfg              config.Config
	codeRepo         CodeRepository
	refreshTokenRepo RefreshTokenRepository
	attemptRepo      AttemptRepository
	notification     NotificationService
	userClient       *users.Client
	sberIDClient     sberid.ClientInterface
}

func NewService(
	cfg config.Config,
	codeRepo CodeRepository,
	refreshTokenRepo RefreshTokenRepository,
	attemptRepo AttemptRepository,
	notification NotificationService,
	userClient *users.Client,
	sberIDClient sberid.ClientInterface,
) *Service {
	return &Service{
		cfg:              cfg,
		codeRepo:         codeRepo,
		refreshTokenRepo: refreshTokenRepo,
		attemptRepo:      attemptRepo,
		notification:     notification,
		userClient:       userClient,
		sberIDClient:     sberIDClient,
	}
}

func (s *Service) validateSignupInput(ctx context.Context, email, firstName, lastName string) error {
	if err := ValidateEmail(email); err != nil {
		slog.ErrorContext(ctx, "invalid email format for signup", "email", email, "error", err)
		return fmt.Errorf("invalid email: %w", err)
	}

	if err := ValidateName(firstName); err != nil {
		slog.ErrorContext(ctx, "invalid first name for signup", "firstName", firstName, "error", err)
		return fmt.Errorf("invalid first name: %w", err)
	}

	if err := ValidateName(lastName); err != nil {
		slog.ErrorContext(ctx, "invalid last name for signup", "lastName", lastName, "error", err)
		return fmt.Errorf("invalid last name: %w", err)
	}

	return nil
}

func (s *Service) isLocallyBlocked(ctx context.Context, email string, attemptType entity.AttemptType) *time.Time {
	localBlock, blockErr := s.attemptRepo.GetLastBlockByEmail(ctx, email, string(attemptType))
	if blockErr != nil && !errors.Is(blockErr, entity.ErrNotFound) {
		slog.ErrorContext(ctx, "error checking local block", "email", email, "type", attemptType, "error", blockErr)
	}

	if blockErr == nil && localBlock.EndBlock.After(time.Now()) {
		slog.WarnContext(ctx, "user is locally blocked", "email", email, "type", attemptType, "blockedTo", localBlock.EndBlock)
		return &localBlock.EndBlock
	}

	return nil
}

func (s *Service) checkSendLimitAuthAndBlock(ctx context.Context, email, ip string, userID uuid.UUID) error {
	since := time.Now().Add(-s.cfg.OTP.CodeSendPeriod)

	attempts, attemptsErr := s.attemptRepo.SendAttemptsByEmailAndIP(ctx, email, ip, entity.AttemptTypeAuth, since)
	if attemptsErr != nil {
		slog.ErrorContext(ctx, "error counting auth send attempts", "email", email, "ip", ip, "error", attemptsErr)
		return fmt.Errorf("failed to check send attempts: %w", attemptsErr)
	}

	if len(attempts) >= s.cfg.OTP.CodeSendLimit {
		blockedTo := time.Now().Add(s.cfg.OTP.CodeSendBlockTime)

		ctx = logger.SetLogType(ctx, "security")

		slog.WarnContext(
			ctx,
			"attempt limit exceeded",
			"email", email,
			"ip", ip,
			"attempt_count", len(attempts),
			"limit", s.cfg.OTP.CodeSendLimit,
		)

		blockErr := s.userClient.BlockUserTemporary(ctx, userID, blockedTo)
		if blockErr != nil {
			slog.ErrorContext(ctx, "failed to block user in MS Users, using local block", "email", email, "userID", userID, "error", blockErr)
			attemptsBlock := entity.AttemptBlock{
				ID:         uuid.Must(uuid.NewV4()),
				Type:       string(entity.AttemptTypeAuth),
				Email:      email,
				IPAddress:  ip,
				StartBlock: time.Now(),
				EndBlock:   blockedTo,
			}

			if addErr := s.attemptRepo.AddAttemptBlocks(ctx, attemptsBlock); addErr != nil {
				slog.ErrorContext(ctx, "failed to add local block", "email", email, "error", addErr)
			}
		}

		slog.ErrorContext(ctx, "user blocked due to excessive attempts",
			"email", email,
			"ip", ip,
			"blocked_until", blockedTo,
			"reason", "send_limit_exceeded",
		)

		if saveErr := s.saveAttemptWithUser(ctx, email, ip, &userID); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save attempt when limit exceeded", "email", email, "error", saveErr)
		}

		return &entity.BlockedError{BlockedTo: &blockedTo}
	}

	return nil
}

func (s *Service) checkSendLimitLocalBlock(ctx context.Context, email, ip string, attemptType entity.AttemptType) error {
	since := time.Now().Add(-s.cfg.OTP.CodeSendPeriod)

	attempts, attemptsErr := s.attemptRepo.SendAttemptsByEmailAndIP(ctx, email, ip, attemptType, since)
	if attemptsErr != nil {
		slog.ErrorContext(ctx, "error counting send attempts", "email", email, "ip", ip, "type", attemptType, "error", attemptsErr)
		return fmt.Errorf("failed to check send attempts: %w", attemptsErr)
	}

	if len(attempts) >= s.cfg.OTP.CodeSendLimit {
		blockedTo := time.Now().Add(s.cfg.OTP.CodeSendBlockTime)

		ctx = logger.SetLogType(ctx, "security")

		slog.WarnContext(
			ctx,
			"attempt limit exceeded",
			"email", email,
			"ip", ip,
			"attempt_count", len(attempts),
			"limit", s.cfg.OTP.CodeSendLimit,
		)

		attemptsBlock := entity.AttemptBlock{
			ID:         uuid.Must(uuid.NewV4()),
			Type:       string(attemptType),
			Email:      email,
			IPAddress:  ip,
			StartBlock: time.Now(),
			EndBlock:   blockedTo,
		}

		if addErr := s.attemptRepo.AddAttemptBlocks(ctx, attemptsBlock); addErr != nil {
			slog.ErrorContext(ctx, "failed to add local block for register", "email", email, "error", addErr)
		}

		slog.ErrorContext(ctx, "user blocked due to excessive attempts",
			"email", email,
			"ip", ip,
			"blocked_until", blockedTo,
			"reason", "send_limit_exceeded",
		)

		if saveErr := s.saveAttempt(ctx, email, ip, attemptType); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save attempt when limit exceeded", "email", email, "error", saveErr)
		}

		return &entity.BlockedError{BlockedTo: &blockedTo}
	}

	return nil
}

func (s *Service) sendAuthCodeFlow(ctx context.Context, email string, userInfo entity.UserInfo, ip string) error {
	slog.InfoContext(ctx, "sending auth code", "email", email, "ip", ip, "userID", userInfo.ID)

	code, genErr := s.generateAndSaveAuthCode(ctx, email)
	if genErr != nil {
		slog.ErrorContext(ctx, "failed to generate auth code", "email", email, "error", genErr)
		return fmt.Errorf("failed to generate code: %w", genErr)
	}

	slog.InfoContext(ctx, "auth code generated, sending email", "email", email, "code", code)
	s.notification.SendEmailVerificationCode(ctx, email, code)

	if err := s.saveAttemptWithUser(ctx, email, ip, &userInfo.ID); err != nil {
		slog.ErrorContext(ctx, "failed to save auth attempt", "email", email, "error", err)
		return fmt.Errorf("failed to save attempt: %w", err)
	}

	slog.InfoContext(ctx, "auth code sent successfully (auto-switched from signup)", "email", email, "ip", ip, "userID", userInfo.ID)

	return nil
}

func (s *Service) sendRegisterCodeFlow(
	ctx context.Context, email, firstName, lastName, ip string,
	privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
) error {
	slog.InfoContext(ctx, "sending register code", "email", email, "ip", ip)

	code, err := s.generateAndSaveCode(ctx, email, &firstName, &lastName, &privacyPolicyAgreed, &newsletterAgreed, &publicDonationsAgreed)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate signup code", "email", email, "error", err)
		return fmt.Errorf("failed to generate code: %w", err)
	}

	slog.InfoContext(ctx, "register code generated, sending email", "email", email, "code", code)
	s.notification.SendEmailVerificationCode(ctx, email, code)

	if err := s.saveAttempt(ctx, email, ip, entity.AttemptTypeRegister); err != nil {
		slog.ErrorContext(ctx, "failed to save signup attempt", "email", email, "error", err)
		return fmt.Errorf("failed to save attempt: %w", err)
	}

	slog.InfoContext(ctx, "signup code sent successfully", "email", email, "ip", ip)

	return nil
}

func (s *Service) SendSignupCode(
	ctx context.Context, email, firstName, lastName string,
	privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
) error {
	if err := s.validateSignupInput(ctx, email, firstName, lastName); err != nil {
		return err
	}

	userInfo, err := s.userClient.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, entity.ErrNotFound) {
		if errors.Is(err, entity.ErrUserBlocked) {
			slog.WarnContext(ctx, "user is blocked in MS Users, cannot send code", "email", email)
			return entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			slog.WarnContext(ctx, "user is deleted in MS Users, cannot send code", "email", email)
			return entity.ErrUserDeleted
		}

		slog.ErrorContext(ctx, "error checking user existence in MS Users", "email", email, "error", err)
		return fmt.Errorf("get user from MS Users: %w", err)
	}

	ipAddr := entity.IPFromCtx(ctx)

	if err == nil {
		slog.InfoContext(ctx, "checking user block status before sending auth code", "email", email, "userID", userInfo.ID, "ip", ipAddr)

		if blockedTo := s.isLocallyBlocked(ctx, email, entity.AttemptTypeAuth); blockedTo != nil {
			slog.WarnContext(ctx, "user is locally blocked, cannot send auth code", "email", email, "ip", ipAddr, "blockedTo", blockedTo)

			if saveErr := s.saveAttemptWithUser(ctx, email, ipAddr, &userInfo.ID); saveErr != nil {
				slog.ErrorContext(ctx, "failed to save attempt when blocked", "email", email, "error", saveErr)
			}

			return &entity.BlockedError{BlockedTo: blockedTo}
		}

		if limitErr := s.checkSendLimitAuthAndBlock(ctx, email, ipAddr, userInfo.ID); limitErr != nil {
			return limitErr
		}

		return s.sendAuthCodeFlow(ctx, email, userInfo, ipAddr)
	}

	slog.InfoContext(ctx, "checking block status before sending register code",
		"email", email, "ip", ipAddr)

	if blockedTo := s.isLocallyBlocked(ctx, email, entity.AttemptTypeRegister); blockedTo != nil {
		slog.WarnContext(ctx, "user is locally blocked, cannot send register code", "email", email, "ip", ipAddr, "blockedTo", blockedTo)

		if saveErr := s.saveAttempt(ctx, email, ipAddr, entity.AttemptTypeRegister); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save attempt when blocked", "email", email, "error", saveErr)
		}

		return &entity.BlockedError{BlockedTo: blockedTo}
	}

	if limitErr := s.checkSendLimitLocalBlock(ctx, email, ipAddr, entity.AttemptTypeRegister); limitErr != nil {
		return limitErr
	}

	return s.sendRegisterCodeFlow(ctx, email, firstName, lastName, ipAddr, privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed)
}

func (s *Service) SendAuthCode(ctx context.Context, email string) error {
	if err := ValidateEmail(email); err != nil {
		slog.ErrorContext(ctx, "invalid email format for auth", "email", email, "error", err)
		return fmt.Errorf("invalid email: %w", err)
	}

	userInfo, err := s.userClient.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			slog.ErrorContext(ctx, "user not found for auth", "email", email)
			return entity.ErrNotFound
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			slog.WarnContext(ctx, "user is blocked in MS Users, cannot send code", "email", email)
			return entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			slog.WarnContext(ctx, "user is deleted in MS Users, cannot send code", "email", email)
			return entity.ErrUserDeleted
		}

		slog.ErrorContext(ctx, "error checking user in MS Users", "email", email, "error", err)
		return fmt.Errorf("get user from MS Users: %w", err)
	}

	ipAddr := entity.IPFromCtx(ctx)

	slog.InfoContext(ctx, "checking user block status before sending auth code",
		"email", email, "userID", userInfo.ID, "ip", ipAddr)

	if blockedTo := s.isLocallyBlocked(ctx, email, entity.AttemptTypeAuth); blockedTo != nil {
		slog.WarnContext(ctx, "user is locally blocked, cannot send auth code", "email", email, "ip", ipAddr, "blockedTo", blockedTo)

		if saveErr := s.saveAttemptWithUser(ctx, email, ipAddr, &userInfo.ID); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save attempt when blocked", "email", email, "error", saveErr)
		}

		return &entity.BlockedError{BlockedTo: blockedTo}
	}

	if limitErr := s.checkSendLimitAuthAndBlock(ctx, email, ipAddr, userInfo.ID); limitErr != nil {
		return limitErr
	}

	code, err := s.generateAndSaveAuthCode(ctx, email)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate auth code", "email", email, "error", err)
		return fmt.Errorf("failed to generate code: %w", err)
	}

	slog.InfoContext(ctx, "auth code generated, sending email", "email", email, "code", code)
	s.notification.SendEmailVerificationCode(ctx, email, code)

	if err := s.saveAttemptWithUser(ctx, email, ipAddr, &userInfo.ID); err != nil {
		slog.ErrorContext(ctx, "failed to save auth attempt", "email", email, "error", err)
		return fmt.Errorf("failed to save attempt: %w", err)
	}

	slog.InfoContext(ctx, "auth code sent successfully", "email", email, "ip", ipAddr, "userID", userInfo.ID)

	return nil
}

//nolint:gocognit
func (s *Service) CheckCode(ctx context.Context, email, code string, action entity.VerificationAction) error {
	ipAddr := entity.IPFromCtx(ctx)
	slog.InfoContext(ctx, "checking verification code", "email", email, "action", action, "ip", ipAddr)

	var attemptType entity.AttemptType
	if action == entity.VerificationActionRegister {
		attemptType = entity.AttemptTypeRegister
	} else {
		attemptType = entity.AttemptTypeAuth
	}

	var userID *uuid.UUID

	if attemptType == entity.AttemptTypeAuth {
		userInfo, userErr := s.userClient.UserByEmail(ctx, email)
		if userErr == nil {
			userID = &userInfo.ID
		} else if !errors.Is(userErr, entity.ErrNotFound) {
			slog.WarnContext(ctx, "error getting user for auth code check", "email", email, "error", userErr)
		}
	}

	if blockedTo := s.isLocallyBlocked(ctx, email, attemptType); blockedTo != nil {
		slog.WarnContext(ctx, "user is locally blocked, cannot check code",
			"email", email, "attemptType", attemptType, "ip", ipAddr, "blockedTo", blockedTo)
		return &entity.BlockedError{BlockedTo: blockedTo}
	}

	savedCode, err := s.codeRepo.FindByEmailAndAction(ctx, email, action)
	if err != nil {
		slog.ErrorContext(ctx, "verification code not found", "email", email, "action", action, "ip", ipAddr, "error", err)

		codeHash, hashErr := s.HashCode(code)
		if hashErr != nil {
			slog.ErrorContext(ctx, "failed to hash code for attempt when code not found", "email", email, "error", hashErr)
		}

		if hashErr != nil {
			codeHash = ""
		}

		if userID != nil {
			if saveErr := s.saveAttemptWithUserAndHash(ctx, email, ipAddr, attemptType, userID, codeHash); saveErr != nil {
				slog.ErrorContext(ctx, "failed to save attempt when code not found (with user)", "email", email, "error", saveErr)
			}
		} else {
			if saveErr := s.saveAttemptWithHash(ctx, email, ipAddr, attemptType, codeHash); saveErr != nil {
				slog.ErrorContext(ctx, "failed to save attempt when code not found", "email", email, "error", saveErr)
			}
		}

		if blockErr := s.checkCodeCheckLimitAndBlock(ctx, email, ipAddr, attemptType, userID); blockErr != nil {
			return blockErr
		}

		return fmt.Errorf("verification code not found: %w", err)
	}

	if time.Now().After(savedCode.ExpirationDate) {
		slog.WarnContext(ctx, "verification code expired", "email", email, "action", action, "ip", ipAddr, "expiredAt", savedCode.ExpirationDate)
		return entity.ErrCodeExpired
	}

	if bcrypt.CompareHashAndPassword([]byte(savedCode.CodeHash), []byte(code)) == nil {
		slog.InfoContext(ctx, "verification code checked successfully", "email", email, "action", action, "ip", ipAddr)

		if err := s.codeRepo.DeleteUsedCodes(ctx); err != nil {
			slog.WarnContext(ctx, "failed to delete used codes after successful check", "email", email, "error", err)
		}

		return nil
	}

	slog.WarnContext(ctx, "invalid verification code", "email", email, "action", action, "ip", ipAddr)

	codeHash, hashErr := s.HashCode(code)
	if hashErr != nil {
		slog.ErrorContext(ctx, "failed to hash code for attempt", "email", email, "error", hashErr)
	}

	if hashErr != nil {
		codeHash = ""
	}

	if userID != nil {
		if saveErr := s.saveAttemptWithUserAndHash(ctx, email, ipAddr, attemptType, userID, codeHash); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save failed attempt with user", "email", email, "error", saveErr)
		}
	} else {
		if saveErr := s.saveAttemptWithHash(ctx, email, ipAddr, attemptType, codeHash); saveErr != nil {
			slog.ErrorContext(ctx, "failed to save failed attempt", "email", email, "error", saveErr)
		}
	}

	if blockErr := s.checkCodeCheckLimitAndBlock(ctx, email, ipAddr, attemptType, userID); blockErr != nil {
		return blockErr
	}

	return entity.ErrCodeInvalid
}

func (s *Service) checkCodeCheckLimitAndBlock(
	ctx context.Context, email, ipAddr string, attemptType entity.AttemptType, userID *uuid.UUID,
) error {
	since := time.Now().Add(-s.cfg.OTP.CodeCheckPeriod)

	attempts, attemptsErr := s.attemptRepo.CheckAttemptsByEmailAndIP(ctx, email, ipAddr, attemptType, since)
	if attemptsErr != nil {
		slog.ErrorContext(ctx, "failed to count check attempts by email and IP", "email", email, "ip", ipAddr, "error", attemptsErr)
		return nil
	}

	if len(attempts) >= s.cfg.OTP.CodeCheckLimit {
		blockedTo := time.Now().Add(s.cfg.OTP.CodeCheckBlockTime)

		ctx = logger.SetLogType(ctx, "security")

		slog.WarnContext(
			ctx,
			"code check limit exceeded",
			"email", email,
			"ip", ipAddr,
			"attempt_count", len(attempts),
			"limit", s.cfg.OTP.CodeCheckLimit,
		)

		if userID != nil {
			blockErr := s.userClient.BlockUserTemporary(ctx, *userID, blockedTo)
			if blockErr != nil {
				slog.ErrorContext(ctx, "failed to block user in MS Users, using local block", "email", email, "userID", *userID, "error", blockErr)

				attemptsBlock := entity.AttemptBlock{
					ID:         uuid.Must(uuid.NewV4()),
					Type:       string(attemptType),
					Email:      email,
					IPAddress:  ipAddr,
					StartBlock: time.Now(),
					EndBlock:   blockedTo,
				}

				if addErr := s.attemptRepo.AddAttemptBlocks(ctx, attemptsBlock); addErr != nil {
					slog.ErrorContext(ctx, "failed to add local block as fallback", "email", email, "error", addErr)
				}
			}
		} else {
			attemptsBlock := entity.AttemptBlock{
				ID:         uuid.Must(uuid.NewV4()),
				Type:       string(attemptType),
				Email:      email,
				IPAddress:  ipAddr,
				StartBlock: time.Now(),
				EndBlock:   blockedTo,
			}

			if addErr := s.attemptRepo.AddAttemptBlocks(ctx, attemptsBlock); addErr != nil {
				slog.ErrorContext(ctx, "failed to add local block for non-existent user", "email", email, "error", addErr)
			}
		}

		slog.ErrorContext(ctx, "user blocked due to code check limit exceeded",
			"email", email,
			"ip", ipAddr,
			"attemptType", attemptType,
			"blocked_until", blockedTo,
			"reason", "check_limit_exceeded",
		)

		return &entity.BlockedError{BlockedTo: &blockedTo}
	}

	return nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*entity.UserTokens, error) {
	pubKey, err := base64.RawStdEncoding.DecodeString(s.validateJWTKey(s.cfg.JWT.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w, key: %s", err, s.cfg.JWT.PublicKey)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	var userClaims entity.UserJwtClaims

	token, err := jwt.ParseWithClaims(refreshToken, &userClaims, func(token *jwt.Token) (any, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse refresh token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid refresh token: %w", entity.ErrInvalidToken)
	}

	if err := s.refreshTokenRepo.FindRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}

	if err := s.refreshTokenRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("delete refresh token: %w", err)
	}

	user := entity.User{ID: userClaims.User.ID, IsFirstEnter: false}

	newTokens, err := s.generateTokens(ctx, user, nil)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	return newTokens, nil
}

func (s *Service) ValidateToken(ctx context.Context, accessToken string) (*entity.User, error) {
	pubKey, err := base64.RawStdEncoding.DecodeString(s.validateJWTKey(s.cfg.JWT.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w, key: %s", err, s.validateJWTKey(s.cfg.JWT.PublicKey))
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	var userClaims entity.UserJwtClaims

	token, err := jwt.ParseWithClaims(accessToken, &userClaims, func(token *jwt.Token) (any, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired: %w", entity.ErrTokenExpired)
		}

		return nil, fmt.Errorf("parse access token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid access token: %w", entity.ErrInvalidToken)
	}

	accessTokenJTI := userClaims.ID
	if accessTokenJTI == "" {
		return nil, fmt.Errorf("access token missing JTI: %w", entity.ErrInvalidToken)
	}

	refreshTokens, err := s.refreshTokenRepo.GetActiveRefreshTokensByUserID(ctx, userClaims.User.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh tokens: %w", err)
	}

	found := false

	for _, refreshTokenStr := range refreshTokens {
		var refreshClaims entity.UserJwtClaims

		refreshToken, parseErr := jwt.ParseWithClaims(refreshTokenStr, &refreshClaims, func(token *jwt.Token) (any, error) {
			_, ok := token.Method.(*jwt.SigningMethodRSA)
			if !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return publicKey, nil
		})

		if parseErr != nil {
			continue
		}

		if refreshToken.Valid && refreshClaims.ID == accessTokenJTI {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("refresh token not found or revoked: %w", entity.ErrTokenRevoked)
	}

	_, err = s.userClient.UserInfoByID(ctx, userClaims.User.ID)
	if err != nil {
		if errors.Is(err, entity.ErrUserBlocked) {
			return nil, entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			return nil, entity.ErrUserDeleted
		}

		slog.WarnContext(ctx, "failed to get user info during token validation", "user_id", userClaims.User.ID, "error", err)
	}

	user := &entity.User{ID: userClaims.User.ID, IsFirstEnter: false}

	return user, nil
}

func (s *Service) RevokeToken(ctx context.Context, userID uuid.UUID) error {
	if err := s.refreshTokenRepo.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

func (s *Service) generateAndSaveCode(
	ctx context.Context, email string, firstName, lastName *string,
	privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed *bool,
) (string, error) {
	code := s.GenerateCode()
	codeHash, err := s.HashCode(code)

	if err != nil {
		return "", fmt.Errorf("hash code: %w", err)
	}

	slog.InfoContext(ctx, "verification code generated", "email", email, "action", "register")

	verificationCode := entity.VerificationCode{
		ID:                    uuid.Must(uuid.NewV4()),
		Email:                 email,
		Action:                entity.VerificationActionRegister,
		CodeHash:              codeHash,
		ExpirationDate:        time.Now().Add(s.cfg.OTP.CodeTTL),
		CreatedAt:             time.Now(),
		FirstName:             firstName,
		LastName:              lastName,
		PrivacyPolicyAgreed:   privacyPolicyAgreed,
		NewsletterAgreed:      newsletterAgreed,
		PublicDonationsAgreed: publicDonationsAgreed,
	}

	if err := s.codeRepo.SaveVerificationCode(ctx, verificationCode); err != nil {
		return "", fmt.Errorf("failed to save verification code: %w", err)
	}

	return code, nil
}

func (s *Service) generateAndSaveAuthCode(ctx context.Context, email string) (string, error) {
	code := s.GenerateCode()
	codeHash, err := s.HashCode(code)

	if err != nil {
		return "", fmt.Errorf("hash code: %w", err)
	}

	slog.InfoContext(ctx, "verification code generated", "email", email, "action", "auth")

	verificationCode := entity.VerificationCode{
		ID:             uuid.Must(uuid.NewV4()),
		Email:          email,
		Action:         entity.VerificationActionAuth,
		CodeHash:       codeHash,
		ExpirationDate: time.Now().Add(s.cfg.OTP.CodeTTL),
		CreatedAt:      time.Now(),
	}

	if err := s.codeRepo.SaveVerificationCode(ctx, verificationCode); err != nil {
		return "", fmt.Errorf("failed to save verification code: %w", err)
	}

	return code, nil
}

func (s *Service) GenerateCode() string {
	newInt := big.NewInt(maxCodeValue)
	n, err := rand.Int(rand.Reader, newInt)

	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%06d", n.Int64())
}

func (s *Service) HashCode(code string) (string, error) {
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(codeHash), nil
}

func (s *Service) generateTokens(ctx context.Context, user entity.User, userInfo *entity.UserInfo) (*entity.UserTokens, error) {
	var info entity.UserInfo

	if userInfo != nil && userInfo.Role.ID != uuid.Nil {
		info = *userInfo
	} else {
		var err error

		info, err = s.userClient.UserInfoByID(ctx, user.ID)
		if err != nil {
			switch {
			case errors.Is(err, entity.ErrUserBlocked):
				return nil, entity.ErrUserBlocked
			case errors.Is(err, entity.ErrUserDeleted):
				return nil, entity.ErrUserDeleted
			case userInfo != nil:
				info = *userInfo
			case errors.Is(err, entity.ErrNotFound) || strings.Contains(err.Error(), "500"):
				info = entity.UserInfo{
					ID:        user.ID,
					IsBlocked: false,
					Role:      entity.UserRole{},
				}
			default:
				return nil, fmt.Errorf("get user info: %w", err)
			}
		}
	}

	accessTokenExpiresAt := time.Now().Add(s.cfg.JWT.AccessTokenExpiry)
	refreshTokenExpiresAt := time.Now().Add(s.cfg.JWT.RefreshTokenExpiry)

	pKey, err := base64.StdEncoding.DecodeString(s.validateJWTKey(s.cfg.JWT.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w, key: %s", err, s.cfg.JWT.PrivateKey)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(pKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	refreshTokenJTI := uuid.Must(uuid.NewV4()).String()

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256,
		entity.UserJwtClaims{
			User: entity.UserJwtInfo{
				ID:        user.ID,
				Role:      info.Role,
				IsBlocked: info.IsBlocked,
			},
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        refreshTokenJTI,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(refreshTokenExpiresAt),
			},
		}).SignedString(privateKey)

	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256,
		entity.UserJwtClaims{
			User: entity.UserJwtInfo{
				ID:        user.ID,
				Role:      info.Role,
				IsBlocked: info.IsBlocked,
			},
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        refreshTokenJTI,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(accessTokenExpiresAt),
			},
		}).SignedString(privateKey)

	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	if err := s.refreshTokenRepo.SaveRefreshToken(ctx, user.ID, refreshToken, refreshTokenExpiresAt); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &entity.UserTokens{
		IsFirstEnter:    user.IsFirstEnter,
		AccessToken:     accessToken,
		RefreshToken:    refreshToken,
		RefreshTokenTTL: s.cfg.JWT.RefreshTokenExpiry,
	}, nil
}

func (s *Service) saveAttempt(ctx context.Context, email, ipAddr string, attemptType entity.AttemptType) error {
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		Email:     email,
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		CodeHash:  "",
	}

	switch attemptType {
	case entity.AttemptTypeAuth, entity.AttemptTypeRegister:
		attempt.Provider = entity.ProviderTypeEmail
	default:
		attempt.Provider = entity.ProviderTypeEmail
	}

	return s.attemptRepo.SaveAttempt(ctx, attempt)
}

func (s *Service) saveAttemptWithHash(ctx context.Context, email, ipAddr string, attemptType entity.AttemptType, codeHash string) error {
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		Email:     email,
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		CodeHash:  codeHash,
	}

	switch attemptType {
	case entity.AttemptTypeAuth, entity.AttemptTypeRegister:
		attempt.Provider = entity.ProviderTypeEmail
	default:
		attempt.Provider = entity.ProviderTypeEmail
	}

	return s.attemptRepo.SaveAttempt(ctx, attempt)
}

func (s *Service) saveAttemptWithUser(ctx context.Context, email, ipAddr string, userID *uuid.UUID) error {
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      entity.AttemptTypeAuth,
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		CodeHash:  "",
		Provider:  entity.ProviderTypeEmail,
	}

	return s.attemptRepo.SaveAttempt(ctx, attempt)
}

func (s *Service) saveAttemptWithUserAndHash(
	ctx context.Context,
	email, ipAddr string,
	attemptType entity.AttemptType,
	userID *uuid.UUID,
	codeHash string,
) error {
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		CodeHash:  codeHash,
	}

	switch attemptType {
	case entity.AttemptTypeAuth, entity.AttemptTypeRegister:
		attempt.Provider = entity.ProviderTypeEmail
	default:
		attempt.Provider = entity.ProviderTypeEmail
	}

	return s.attemptRepo.SaveAttempt(ctx, attempt)
}

func (s *Service) validateJWTKey(key string) string {
	return strings.TrimSpace(strings.NewReplacer(
		`\`, "", `"`, "", " ", "", "\n", "", "\r", "", "{", "", "}", "",
	).Replace(key))
}
func (s *Service) Authenticate(ctx context.Context, email, code string) (*entity.UserTokens, error) {
	err := s.CheckCode(ctx, email, code, entity.VerificationActionAuth)
	if err != nil {
		return nil, err
	}

	savedCode, err := s.codeRepo.FindByEmailAndAction(ctx, email, entity.VerificationActionAuth)
	if err != nil {
		return nil, fmt.Errorf("verification code not found: %w", err)
	}

	userInfo, err := s.userClient.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, entity.ErrUserBlocked) {
			slog.WarnContext(ctx, "user is blocked", "email", email)
			return nil, entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			slog.WarnContext(ctx, "user is deleted", "email", email)
			return nil, entity.ErrUserDeleted
		}

		slog.ErrorContext(ctx, "user not found in MS Users", "email", email, "error", err)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if err := s.codeRepo.DeleteCode(ctx, savedCode.ID); err != nil {
		return nil, fmt.Errorf("failed to delete verification code: %w", err)
	}

	user := entity.User{
		ID:           userInfo.ID,
		Email:        email,
		IsFirstEnter: false,
	}

	return s.generateTokens(ctx, user, &userInfo)
}

func (s *Service) DeleteExpiredCode(ctx context.Context) error {
	if err := s.codeRepo.DeleteExpiredCode(ctx); err != nil {
		return fmt.Errorf("delete expired codes: %w", err)
	}

	return nil
}

func (s *Service) DeleteExpiredTokens(ctx context.Context) error {
	if err := s.refreshTokenRepo.CleanExpired(ctx); err != nil {
		return fmt.Errorf("delete expired refresh tokens: %w", err)
	}

	return nil
}

func (s *Service) findVerificationCode(ctx context.Context, email string) (entity.VerificationCode, entity.VerificationAction, error) {
	registerCode, regErr := s.codeRepo.FindByEmailAndAction(ctx, email, entity.VerificationActionRegister)
	authCode, authErr := s.codeRepo.FindByEmailAndAction(ctx, email, entity.VerificationActionAuth)

	if regErr != nil && authErr != nil {
		slog.ErrorContext(ctx, "verification code not found", "email", email, "registerErr", regErr, "authErr", authErr)
		return entity.VerificationCode{}, "", fmt.Errorf("verification code not found: %w", regErr)
	}

	switch {
	case regErr == nil && authErr == nil:
		if registerCode.CreatedAt.After(authCode.CreatedAt) {
			return registerCode, entity.VerificationActionRegister, nil
		}

		return authCode, entity.VerificationActionAuth, nil
	case regErr == nil:
		return registerCode, entity.VerificationActionRegister, nil
	default:
		return authCode, entity.VerificationActionAuth, nil
	}
}

//nolint:funlen,gocognit
func (s *Service) SigningRegister(ctx context.Context, email, code, firstName, lastName string) (entity.UserTokens, error) {
	if err := ValidateEmail(email); err != nil {
		return entity.UserTokens{}, fmt.Errorf("invalid email: %w", err)
	}

	if err := ValidateName(firstName); err != nil {
		return entity.UserTokens{}, fmt.Errorf("invalid first name: %w", err)
	}

	if err := ValidateName(lastName); err != nil {
		return entity.UserTokens{}, fmt.Errorf("invalid last name: %w", err)
	}

	ipAddr := entity.IPFromCtx(ctx)

	if blockedTo := s.isLocallyBlocked(ctx, email, entity.AttemptTypeRegister); blockedTo != nil {
		slog.WarnContext(ctx, "user is locally blocked, cannot check code for register",
			"email", email, "ip", ipAddr, "blockedTo", blockedTo)
		return entity.UserTokens{}, &entity.BlockedError{BlockedTo: blockedTo}
	}

	if err := s.CheckCode(ctx, email, code, entity.VerificationActionRegister); err != nil {
		slog.WarnContext(ctx, "code verification failed for register", "email", email, "ip", ipAddr, "error", err)
		return entity.UserTokens{}, err
	}

	slog.InfoContext(ctx, "code verified successfully for register", "email", email, "ip", ipAddr)

	checkedCode, findCheckedErr := s.codeRepo.FindByEmailAndAction(ctx, email, entity.VerificationActionRegister)
	if findCheckedErr != nil {
		return entity.UserTokens{}, fmt.Errorf("verification code not found after check: %w", findCheckedErr)
	}

	existingUserCheck, checkErr := s.userClient.UserByEmail(ctx, email)
	if checkErr != nil {
		if errors.Is(checkErr, entity.ErrUserBlocked) {
			slog.WarnContext(ctx, "user is blocked in MS Users during register", "email", email, "ip", ipAddr)
			return entity.UserTokens{}, entity.ErrUserBlocked
		}

		if errors.Is(checkErr, entity.ErrUserDeleted) {
			slog.WarnContext(ctx, "user is deleted in MS Users during register", "email", email, "ip", ipAddr)
			return entity.UserTokens{}, entity.ErrUserDeleted
		}

		if !errors.Is(checkErr, entity.ErrNotFound) {
			slog.ErrorContext(ctx, "failed to check user existence", "email", email, "error", checkErr)
			return entity.UserTokens{}, fmt.Errorf("check user: %w", checkErr)
		}
	}

	if checkErr == nil {
		slog.WarnContext(ctx, "user already exists, using existing account instead of creating new",
			"email", email, "userID", existingUserCheck.ID)

		user := entity.User{
			ID:           existingUserCheck.ID,
			Email:        email,
			IsFirstEnter: false,
		}

		if err := s.codeRepo.DeleteCode(ctx, checkedCode.ID); err != nil {
			return entity.UserTokens{}, fmt.Errorf("failed to delete verification code: %w", err)
		}

		codeHash, hashErr := s.HashCode(code)
		if hashErr != nil {
			slog.ErrorContext(ctx, "failed to hash code for success attempt", "email", email, "error", hashErr)
		}

		saveErr := s.saveAttemptWithUserAndHash(ctx, email, entity.IPFromCtx(ctx), entity.AttemptTypeRegister, &user.ID, codeHash)
		if saveErr != nil {
			slog.ErrorContext(ctx, "failed to save success attempt", "email", email, "error", saveErr)
		}

		tokens, err := s.generateTokens(ctx, user, &existingUserCheck)
		if err != nil {
			return entity.UserTokens{}, fmt.Errorf("generate tokens: %w", err)
		}

		return *tokens, nil
	}

	privacyPolicyAgreed := false
	newsletterAgreed := false
	publicDonationsAgreed := false

	if checkedCode.PrivacyPolicyAgreed != nil {
		privacyPolicyAgreed = *checkedCode.PrivacyPolicyAgreed
	}

	if checkedCode.NewsletterAgreed != nil {
		newsletterAgreed = *checkedCode.NewsletterAgreed
	}

	if checkedCode.PublicDonationsAgreed != nil {
		publicDonationsAgreed = *checkedCode.PublicDonationsAgreed
	}

	userID, err := s.userClient.CreateUser(ctx, users.CreateUserRequest{
		Email:                 email,
		FirstName:             firstName,
		LastName:              lastName,
		PrivacyPolicyAgreed:   privacyPolicyAgreed,
		NewsletterAgreed:      newsletterAgreed,
		PublicDonationsAgreed: publicDonationsAgreed,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to create user in MS Users", "email", email, "error", err)
		return entity.UserTokens{}, fmt.Errorf("failed to create user: %w", err)
	}

	user := entity.User{
		ID:           userID,
		Email:        email,
		IsFirstEnter: true,
	}

	if err := s.codeRepo.DeleteCode(ctx, checkedCode.ID); err != nil {
		return entity.UserTokens{}, fmt.Errorf("failed to delete verification code: %w", err)
	}

	codeHash, hashErr := s.HashCode(code)
	if hashErr != nil {
		slog.ErrorContext(ctx, "failed to hash code for success attempt", "email", email, "error", hashErr)
	}

	saveErr := s.saveAttemptWithUserAndHash(ctx, email, entity.IPFromCtx(ctx), entity.AttemptTypeRegister, &user.ID, codeHash)
	if saveErr != nil {
		slog.ErrorContext(ctx, "failed to save success attempt", "email", email, "error", saveErr)
	}

	createdUserInfo, getUserErr := s.userClient.UserByEmail(ctx, email)
	if getUserErr != nil {
		slog.ErrorContext(ctx, "failed to get created user info", "user_id", userID, "error", getUserErr)
	}

	var userInfoForTokens *entity.UserInfo
	if getUserErr == nil {
		userInfoForTokens = &createdUserInfo
	}

	tokens, err := s.generateTokens(ctx, user, userInfoForTokens)
	if err != nil {
		return entity.UserTokens{}, fmt.Errorf("generate tokens: %w", err)
	}

	return *tokens, nil
}

func (s *Service) SigningAuth(ctx context.Context, email, code string) (entity.UserTokens, error) {
	if err := ValidateEmail(email); err != nil {
		return entity.UserTokens{}, fmt.Errorf("invalid email: %w", err)
	}

	ipAddr := entity.IPFromCtx(ctx)

	userInfo, err := s.userClient.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			slog.ErrorContext(ctx, "user not found for auth", "email", email)
			return entity.UserTokens{}, entity.ErrNotFound
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			slog.WarnContext(ctx, "user is blocked in MS Users during auth", "email", email, "ip", ipAddr)
			return entity.UserTokens{}, entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			slog.WarnContext(ctx, "user is deleted in MS Users during auth", "email", email, "ip", ipAddr)
			return entity.UserTokens{}, entity.ErrUserDeleted
		}

		slog.ErrorContext(ctx, "failed to check user existence", "email", email, "error", err)
		return entity.UserTokens{}, fmt.Errorf("check user: %w", err)
	}

	if blockedTo := s.isLocallyBlocked(ctx, email, entity.AttemptTypeAuth); blockedTo != nil {
		slog.WarnContext(ctx, "user is locally blocked, cannot check code for auth",
			"email", email, "userID", userInfo.ID, "ip", ipAddr, "blockedTo", blockedTo)

		return entity.UserTokens{}, &entity.BlockedError{BlockedTo: blockedTo}
	}

	if err := s.CheckCode(ctx, email, code, entity.VerificationActionAuth); err != nil {
		slog.WarnContext(ctx, "code verification failed for auth", "email", email, "userID", userInfo.ID, "ip", ipAddr, "error", err)
		return entity.UserTokens{}, err
	}

	slog.InfoContext(ctx, "code verified successfully for auth", "email", email, "userID", userInfo.ID, "ip", ipAddr)

	checkedCode, findCheckedErr := s.codeRepo.FindByEmailAndAction(ctx, email, entity.VerificationActionAuth)
	if findCheckedErr != nil {
		return entity.UserTokens{}, fmt.Errorf("verification code not found after check: %w", findCheckedErr)
	}

	user := entity.User{
		ID:           userInfo.ID,
		Email:        email,
		IsFirstEnter: false,
	}

	if err := s.codeRepo.DeleteCode(ctx, checkedCode.ID); err != nil {
		return entity.UserTokens{}, fmt.Errorf("failed to delete verification code: %w", err)
	}

	codeHash, hashErr := s.HashCode(code)
	if hashErr != nil {
		slog.ErrorContext(ctx, "failed to hash code for success attempt", "email", email, "error", hashErr)
	}

	if saveErr := s.saveAttemptWithUserAndHash(ctx, email, entity.IPFromCtx(ctx), entity.AttemptTypeAuth, &user.ID, codeHash); saveErr != nil {
		slog.ErrorContext(ctx, "failed to save success attempt", "email", email, "error", saveErr)
	}

	tokens, err := s.generateTokens(ctx, user, &userInfo)
	if err != nil {
		return entity.UserTokens{}, fmt.Errorf("generate tokens: %w", err)
	}

	return *tokens, nil
}

func (s *Service) Signing(ctx context.Context, email, code string) (entity.UserTokens, error) {
	if err := ValidateEmail(email); err != nil {
		return entity.UserTokens{}, fmt.Errorf("invalid email: %w", err)
	}

	savedCode, _, err := s.findVerificationCode(ctx, email)
	if err != nil {
		return s.SigningAuth(ctx, email, code)
	}

	if savedCode.FirstName != nil && savedCode.LastName != nil {
		return s.SigningRegister(ctx, email, code, *savedCode.FirstName, *savedCode.LastName)
	}

	return s.SigningAuth(ctx, email, code)
}

func (s *Service) saveAttemptWithSberID(
	ctx context.Context,
	email, ipAddr string,
	attemptType entity.AttemptType,
	userID *uuid.UUID,
) error {
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
		IPAddress: ipAddr,
		CodeHash:  "",
		Provider:  entity.ProviderTypeSberID,
	}

	return s.attemptRepo.SaveAttempt(ctx, attempt)
}

//nolint:gocognit,funlen,gocyclo,maintidx
func (s *Service) RegisterWithSberID(
	ctx context.Context, code string,
	privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
) (*entity.UserTokens, error) {
	ipAddr := entity.IPFromCtx(ctx)
	slog.InfoContext(ctx, "registering with sber id", "ip", ipAddr)

	tokenResp, err := s.sberIDClient.ExchangeCodeForTokens(ctx, code, s.cfg.SberID.RedirectURI)
	if err != nil {
		slog.ErrorContext(ctx, "failed to exchange code for tokens", "error", err, "ip", ipAddr)
		return nil, fmt.Errorf("exchange code for tokens: %w", err)
	}

	sberUserInfo, err := s.sberIDClient.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user info from sber id", "error", err, "ip", ipAddr)
		return nil, fmt.Errorf("get user info: %w", err)
	}

	slog.InfoContext(ctx, "received user info from sber id",
		"sub", sberUserInfo.Sub,
		"sub_alt", sberUserInfo.SubAlt,
		"email", sberUserInfo.Email,
		"ip", ipAddr)

	if err := ValidateSberIDSub(sberUserInfo.Sub, sberUserInfo.SubAlt); err != nil {
		slog.ErrorContext(ctx, "invalid sub/sub_alt", "error", err)
		return nil, entity.ErrSberIDInvalidRequest
	}

	var (
		foundUser *entity.UserInfo
		isNewUser bool
	)

	if sberUserInfo.Sub != "" || sberUserInfo.SubAlt != "" {
		ui, err := s.userClient.SearchUser(ctx, "", sberUserInfo.Sub, sberUserInfo.SubAlt)
		if err == nil {
			foundUser = &ui

			if foundUser.Email != sberUserInfo.Email {
				slog.InfoContext(ctx, "email mismatch detected, updating user data and requiring selection",
					"db_email", foundUser.Email,
					"sber_email", sberUserInfo.Email,
					"user_id", foundUser.ID)

				var phone, birthdate, sub, subAlt *string
				if sberUserInfo.PhoneNumber != "" {
					phone = &sberUserInfo.PhoneNumber
				}

				if sberUserInfo.Birthdate != "" {
					birthdate = &sberUserInfo.Birthdate
				}

				if sberUserInfo.Sub != "" {
					sub = &sberUserInfo.Sub
				}

				if sberUserInfo.SubAlt != "" {
					subAlt = &sberUserInfo.SubAlt
				}

				bindReq := users.UpdateUserRequest{
					UserID:     &foundUser.ID,
					Email:      foundUser.Email,
					FirstName:  sberUserInfo.GivenName,
					LastName:   sberUserInfo.FamilyName,
					MiddleName: sberUserInfo.MiddleName,
					Sub:        sub,
					SubAlt:     subAlt,
					Phone:      phone,
					Birthdate:  birthdate,
				}
				if err := s.userClient.UpdateUser(ctx, bindReq); err != nil && !errors.Is(err, entity.ErrNotFound) {
					slog.ErrorContext(ctx, "failed to update user with sber data before email selection",
						"error", err,
						"user_id", foundUser.ID)
				} else {
					slog.InfoContext(ctx, "successfully updated user data from sber before email selection",
						"user_id", foundUser.ID)
				}

				return nil, &entity.EmailSelectionError{
					UserID: foundUser.ID,
					Emails: []string{foundUser.Email, sberUserInfo.Email},
				}
			}
		} else if !errors.Is(err, entity.ErrNotFound) {
			if errors.Is(err, entity.ErrUserBlocked) {
				return nil, entity.ErrUserBlocked
			}

			if errors.Is(err, entity.ErrUserDeleted) {
				return nil, entity.ErrUserDeleted
			}
			return nil, fmt.Errorf("search user by sub: %w", err)
		}
	}

	if foundUser == nil {
		ui, err := s.userClient.UserByEmail(ctx, sberUserInfo.Email)
		if err == nil {
			slog.InfoContext(ctx, "found user by email",
				"user_id", ui.ID,
				"email", ui.Email,
				"role_id", ui.Role.ID,
				"role_name", ui.Role.Name,
				"is_blocked", ui.IsBlocked)

			foundUser = &ui
		} else if !errors.Is(err, entity.ErrNotFound) {
			if errors.Is(err, entity.ErrUserBlocked) {
				return nil, entity.ErrUserBlocked
			}

			if errors.Is(err, entity.ErrUserDeleted) {
				return nil, entity.ErrUserDeleted
			}
			return nil, fmt.Errorf("search user by email: %w", err)
		}
	}

	if foundUser == nil {
		var phone, birthdate, sub, subAlt *string
		if sberUserInfo.PhoneNumber != "" {
			phone = &sberUserInfo.PhoneNumber
		}

		if sberUserInfo.Birthdate != "" {
			birthdate = &sberUserInfo.Birthdate
		}

		if sberUserInfo.Sub != "" {
			sub = &sberUserInfo.Sub
		}

		if sberUserInfo.SubAlt != "" {
			subAlt = &sberUserInfo.SubAlt
		}

		newID, err := s.userClient.CreateUser(ctx, users.CreateUserRequest{
			Email:                 sberUserInfo.Email,
			FirstName:             sberUserInfo.GivenName,
			LastName:              sberUserInfo.FamilyName,
			MiddleName:            sberUserInfo.MiddleName,
			Phone:                 phone,
			Birthdate:             birthdate,
			Sub:                   sub,
			SubAlt:                subAlt,
			PrivacyPolicyAgreed:   privacyPolicyAgreed,
			NewsletterAgreed:      newsletterAgreed,
			PublicDonationsAgreed: publicDonationsAgreed,
		})
		if err != nil {
			ui, findErr := s.userClient.UserByEmail(ctx, sberUserInfo.Email)
			if findErr != nil {
				return nil, fmt.Errorf("create user: %w", err)
			}

			foundUser = &ui
		} else {
			ui, err := s.userClient.UserInfoByID(ctx, newID)
			if err != nil {
				return nil, fmt.Errorf("get user after create: %w", err)
			}

			foundUser = &ui
			isNewUser = true
		}
	}

	var phone2, birthdate2, sub2, subAlt2 *string
	if sberUserInfo.PhoneNumber != "" {
		phone2 = &sberUserInfo.PhoneNumber
	}

	if sberUserInfo.Birthdate != "" {
		birthdate2 = &sberUserInfo.Birthdate
	}

	if sberUserInfo.Sub != "" {
		sub2 = &sberUserInfo.Sub
	}

	if sberUserInfo.SubAlt != "" {
		subAlt2 = &sberUserInfo.SubAlt
	}

	bindReq := users.UpdateUserRequest{
		Email:      sberUserInfo.Email,
		Sub:        sub2,
		SubAlt:     subAlt2,
		MiddleName: sberUserInfo.MiddleName,
		Phone:      phone2,
		Birthdate:  birthdate2,
	}
	if err := s.userClient.UpdateUser(ctx, bindReq); err != nil && !errors.Is(err, entity.ErrNotFound) {
		return nil, fmt.Errorf("bind sber id: %w", err)
	}

	attemptType := entity.AttemptTypeAuth
	if isNewUser {
		attemptType = entity.AttemptTypeRegister
	}

	if saveErr := s.saveAttemptWithSberID(ctx, sberUserInfo.Email, ipAddr, attemptType, &foundUser.ID); saveErr != nil {
		slog.ErrorContext(ctx, "failed to save attempt", "email", sberUserInfo.Email, "error", saveErr)
	}

	user := entity.User{
		ID:           foundUser.ID,
		Email:        sberUserInfo.Email,
		IsFirstEnter: isNewUser,
	}

	slog.InfoContext(ctx, "generating tokens with user data",
		"user_id", foundUser.ID,
		"role_id", foundUser.Role.ID,
		"role_name", foundUser.Role.Name,
		"is_blocked", foundUser.IsBlocked,
		"is_new_user", isNewUser)

	tokens, err := s.generateTokens(ctx, user, foundUser)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	slog.InfoContext(ctx, "successfully registered/authenticated with sber id",
		"user_id", foundUser.ID,
		"email", sberUserInfo.Email,
		"is_new_user", isNewUser,
		"ip", ipAddr)

	return tokens, nil
}

func (s *Service) UpdateEmailAndAuthorize(ctx context.Context, userID uuid.UUID, email string) (*entity.UserTokens, error) {
	ipAddr := entity.IPFromCtx(ctx)
	slog.InfoContext(ctx, "updating email and authorizing", "user_id", userID, "email", email, "ip", ipAddr)

	if err := ValidateEmail(email); err != nil {
		slog.ErrorContext(ctx, "invalid email format", "email", email, "error", err)
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	foundUser, err := s.userClient.UserInfoByID(ctx, userID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			return nil, entity.ErrNotFound
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			return nil, entity.ErrUserBlocked
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			return nil, entity.ErrUserDeleted
		}
		return nil, fmt.Errorf("search user: %w", err)
	}

	existingUser, err := s.userClient.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, entity.ErrNotFound) {
		slog.ErrorContext(ctx, "failed to check email availability", "email", email, "error", err)
		return nil, fmt.Errorf("check email: %w", err)
	}

	if err == nil && existingUser.ID != userID {
		slog.WarnContext(ctx, "email already taken by another user",
			"email", email,
			"requested_user_id", userID,
			"existing_user_id", existingUser.ID)

		return nil, entity.ErrAlreadyExists
	}

	updateReq := users.UpdateUserRequest{
		UserID: &userID,
		Email:  email,
	}

	if err := s.userClient.UpdateUser(ctx, updateReq); err != nil {
		slog.ErrorContext(ctx, "failed to update user email", "email", email, "error", err)
		return nil, fmt.Errorf("update user email: %w", err)
	}

	if saveErr := s.saveAttemptWithSberID(ctx, email, ipAddr, entity.AttemptTypeAuth, &foundUser.ID); saveErr != nil {
		slog.ErrorContext(ctx, "failed to save attempt", "email", email, "error", saveErr)
	}

	user := entity.User{
		ID:           foundUser.ID,
		Email:        email,
		IsFirstEnter: false,
	}

	foundUser.Email = email

	tokens, err := s.generateTokens(ctx, user, &foundUser)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	slog.InfoContext(ctx, "successfully updated email and authorized",
		"user_id", foundUser.ID,
		"email", email,
		"ip", ipAddr)

	return tokens, nil
}
