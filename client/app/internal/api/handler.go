package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/client/internal/entity"
	"github.com/samandr77/microservices/client/internal/service"
	"github.com/samandr77/microservices/client/pkg/logger"
)

type Service interface {
	CreateUserByEmail(
		ctx context.Context,
		email, firstName, lastName string,
		privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
	) (uuid.UUID, error)
	CreateUserBySberID(ctx context.Context, sberData *service.SberIDData) (uuid.UUID, error)
	MergeUserData(ctx context.Context, userID uuid.UUID, sberData *service.SberIDData) error
	UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileData *service.ProfileUpdateData) error
	UpdateUserProfileInternal(ctx context.Context, userID uuid.UUID, profileData *service.ProfileUpdateData) error
	UpdateUserEmail(ctx context.Context, userID uuid.UUID, newEmail string) error
	FindUserByEmail(ctx context.Context, email string) (uuid.UUID, error)
	SearchUser(ctx context.Context, email, sub, subAlt *string) (*entity.User, error)
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*entity.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error)
	CheckUserExists(ctx context.Context, userID uuid.UUID) (bool, error)
	GetUserBlock(ctx context.Context, userID uuid.UUID) (*entity.UserBlock, error)
	GetDefaultRole(ctx context.Context) (uuid.UUID, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRole(ctx context.Context, userID uuid.UUID) (*entity.Role, error)
	ListAllRoles(ctx context.Context) ([]*entity.Role, error)
	BlockUser(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error
	BlockUserBySecurity(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error
	BlockUserInternal(ctx context.Context, userID uuid.UUID, blockDuration *time.Duration) error
	UnblockUser(ctx context.Context, userID uuid.UUID) error
	UnblockUserBySecurity(ctx context.Context, userID uuid.UUID) error
	ProcessExpiredTemporaryBlocks(ctx context.Context) error
	MarkAsDeleted(ctx context.Context, userID uuid.UUID, accessToken string) error
	RestoreDeletedAccount(ctx context.Context, userID uuid.UUID) error
	RestoreUserByID(ctx context.Context, userID uuid.UUID) error
	CleanupExpiredDeletedAccounts(ctx context.Context) error
	ValidateUserPermission(ctx context.Context, userID uuid.UUID, permission string) error
}

type Handler struct {
	s Service
}

func NewHandler(s Service) *Handler {
	return &Handler{
		s: s,
	}
}

// @Summary Проверка состояния сервиса
// @Description Проверяет, что сервер работает
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {string} string "Сервер работает!"
// @Router /api/health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Сервер работает!\n"))
}

type UpdateUserRequest struct {
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	Sub        *string    `json:"sub,omitempty"`
	SubAlt     *string    `json:"sub_alt,omitempty"`
	LastName   *string    `json:"last_name,omitempty"`
	FirstName  *string    `json:"first_name,omitempty"`
	MiddleName *string    `json:"middle_name,omitempty"`
	Email      *string    `json:"email,omitempty"`
	Phone      *string    `json:"phone,omitempty"`
	Birthdate  *string    `json:"birthdate,omitempty"`
	City       *string    `json:"city,omitempty"`
	SchoolName *string    `json:"school_name,omitempty"`

	PlaceOfEducation *string `json:"place_of_education,omitempty"`
	AddressReg       *string `json:"address_reg,omitempty"`
	Series           *string `json:"series,omitempty"`
	Number           *string `json:"number,omitempty"`
	IssuedBy         *string `json:"issued_by,omitempty"`
	IssuedDate       *string `json:"issued_date,omitempty"`
	Code             *string `json:"code,omitempty"`
	PersonalInfo     *string `json:"personal_info,omitempty"`

	PrivacyPolicyAgreed   *bool `json:"privacy_policy_agreed,omitempty"`
	NewsletterAgreed      *bool `json:"newsletter_agreed,omitempty"`
	PublicDonationsAgreed *bool `json:"public_donations_agreed,omitempty"`
}

type CreateUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
}

type UpdateUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
}
type ErrorResponse struct {
	Message string `json:"message"`
}

type CreateUserRequest struct {
	Email                 string  `json:"email"`
	FirstName             string  `json:"first_name"`
	LastName              string  `json:"last_name"`
	MiddleName            *string `json:"middle_name,omitempty"`
	Phone                 *string `json:"phone,omitempty"`
	Birthdate             *string `json:"birthdate,omitempty"`
	Sub                   *string `json:"sub,omitempty"`
	SubAlt                *string `json:"sub_alt,omitempty"`
	City                  *string `json:"city,omitempty"`
	SchoolName            *string `json:"school_name,omitempty"`
	PlaceOfEducation      *string `json:"place_of_education,omitempty"`
	AddressReg            *string `json:"address_reg,omitempty"`
	Series                *string `json:"series,omitempty"`
	Number                *string `json:"number,omitempty"`
	IssuedBy              *string `json:"issued_by,omitempty"`
	IssuedDate            *string `json:"issued_date,omitempty"`
	Code                  *string `json:"code,omitempty"`
	PersonalInfo          *string `json:"personal_info,omitempty"`
	PrivacyPolicyAgreed   bool    `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool    `json:"newsletter_agreed"`
	PublicDonationsAgreed bool    `json:"public_donations_agreed"`
}

// @Summary Создание пользователя
// @Description Создает нового пользователя (по email или через Сбер ID)
// @Tags users
// @Accept json
// @Produce json
// @Param request body CreateUserRequest true "Запрос на создание пользователя"
// @Success 201 {object} CreateUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Router /internal/users/create [post]
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "user_action")

	var rawRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&rawRequest); err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgBadRequest)
		return
	}

	var userID uuid.UUID

	var err error

	if rawRequest["sub"] != nil || rawRequest["sub_alt"] != nil {
		userID, err = h.createUserBySberID(ctx, w, rawRequest)
	} else {
		userID, err = h.createUserByEmail(ctx, w, rawRequest)
	}

	if err != nil {
		handleUserError(ctx, w, err)
		return
	}

	slog.InfoContext(ctx, "User created", "user_id", userID, "action", "create")

	sendJSON(ctx, w, http.StatusCreated, CreateUserResponse{
		UserID: userID,
	})
}

// @Summary Обновление пользователя
// @Description Обновляет данные пользователя
// @Tags users
// @Accept json
// @Produce json
// @Param request body UpdateUserRequest true "Запрос на обновление пользователя"
// @Success 200 {object} UpdateUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Router /internal/users/update [put]
func (h *Handler) UpdateUserInternal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgInvalidRequest)
		return
	}

	if req.UserID == nil && req.Sub == nil && req.SubAlt == nil {
		sendErr(ctx, w, http.StatusBadRequest, nil, "Необходимо указать user_id, sub или sub_alt для идентификации пользователя")
		return
	}

	userID, err := h.updateUserInternal(ctx, w, &req)
	if err != nil {
		handleUserError(ctx, w, err)
		return
	}

	sendJSON(ctx, w, http.StatusOK, UpdateUserResponse{
		UserID: userID,
	})
}

// @Summary Обновление профиля пользователя
// @Description Обновляет профиль авторизованного пользователя из личного кабинета
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body service.ProfileUpdateData true "Запрос на обновление профиля"
// @Success 200 {object} EmptyResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Router /users/update [put]
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "user_action")

	user, err := entity.UserFromContext(ctx)
	if err != nil {
		sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)
		return
	}

	var req service.ProfileUpdateData
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgInvalidRequest)
		return
	}

	if err := service.ValidateProfileFields(&req); err != nil {
		handleUserError(ctx, w, err)
		return
	}

	req.LastName = normalizeStringPtr(req.LastName)
	req.FirstName = normalizeStringPtr(req.FirstName)
	req.MiddleName = normalizeStringPtr(req.MiddleName)
	req.Phone = normalizeStringPtr(req.Phone)
	req.City = normalizeStringPtr(req.City)
	req.SchoolName = normalizeStringPtr(req.SchoolName)
	req.PlaceOfEducation = normalizeStringPtr(req.PlaceOfEducation)
	req.AddressReg = normalizeStringPtr(req.AddressReg)
	req.Series = normalizeStringPtr(req.Series)
	req.Number = normalizeStringPtr(req.Number)
	req.IssuedBy = normalizeStringPtr(req.IssuedBy)
	req.Code = normalizeStringPtr(req.Code)
	req.PersonalInfo = normalizeStringPtr(req.PersonalInfo)

	if req.Birthdate != nil {
		normalized, err := parseBirthdate(req.Birthdate)
		if err != nil {
			sendErr(ctx, w, http.StatusBadRequest, err, err.Error())
			return
		}

		req.Birthdate = normalized
	}

	if req.IssuedDate != nil {
		normalized, err := parseIssuedDate(req.IssuedDate)
		if err != nil {
			sendErr(ctx, w, http.StatusBadRequest, err, err.Error())
			return
		}

		req.IssuedDate = normalized
	}

	if err := h.s.UpdateUserProfile(ctx, user.UserID, &req); err != nil {
		handleUserError(ctx, w, err)
		return
	}

	slog.InfoContext(ctx, "User profile updated", "user_id", user.UserID, "action", "update")

	sendJSON(ctx, w, http.StatusOK, EmptyResponse{})
}

//nolint:gocyclo,revive,funlen,unparam
func (h *Handler) updateUserInternal(ctx context.Context, w http.ResponseWriter, req *UpdateUserRequest) (uuid.UUID, error) {
	profileData := &service.ProfileUpdateData{
		LastName:         req.LastName,
		FirstName:        req.FirstName,
		MiddleName:       req.MiddleName,
		Phone:            req.Phone,
		Birthdate:        req.Birthdate,
		City:             req.City,
		SchoolName:       req.SchoolName,
		PlaceOfEducation: req.PlaceOfEducation,
		AddressReg:       req.AddressReg,
		Series:           req.Series,
		Number:           req.Number,
		IssuedBy:         req.IssuedBy,
		IssuedDate:       req.IssuedDate,
		Code:             req.Code,
		PersonalInfo:     req.PersonalInfo,
	}

	if err := service.ValidateProfileFields(profileData); err != nil {
		return uuid.Nil, err
	}

	if req.Email != nil {
		if err := service.ValidateEmail(*req.Email); err != nil {
			return uuid.Nil, err
		}
	}

	req.Sub = normalizeStringPtr(req.Sub)
	req.SubAlt = normalizeStringPtr(req.SubAlt)
	req.LastName = normalizeStringPtr(req.LastName)
	req.FirstName = normalizeStringPtr(req.FirstName)
	req.MiddleName = normalizeStringPtr(req.MiddleName)
	req.Phone = normalizeStringPtr(req.Phone)
	req.City = normalizeStringPtr(req.City)
	req.SchoolName = normalizeStringPtr(req.SchoolName)
	req.PlaceOfEducation = normalizeStringPtr(req.PlaceOfEducation)
	req.AddressReg = normalizeStringPtr(req.AddressReg)
	req.Series = normalizeStringPtr(req.Series)
	req.Number = normalizeStringPtr(req.Number)
	req.IssuedBy = normalizeStringPtr(req.IssuedBy)
	req.Code = normalizeStringPtr(req.Code)
	req.PersonalInfo = normalizeStringPtr(req.PersonalInfo)
	req.Birthdate = normalizeDate(req.Birthdate)
	req.IssuedDate = normalizeDate(req.IssuedDate)
	profileData.LastName = req.LastName
	profileData.FirstName = req.FirstName
	profileData.MiddleName = req.MiddleName
	profileData.Phone = req.Phone
	profileData.City = req.City
	profileData.SchoolName = req.SchoolName
	profileData.PlaceOfEducation = req.PlaceOfEducation
	profileData.AddressReg = req.AddressReg
	profileData.Series = req.Series
	profileData.Number = req.Number
	profileData.IssuedBy = req.IssuedBy
	profileData.Code = req.Code
	profileData.PersonalInfo = req.PersonalInfo

	var birthdate *string

	var err error

	if req.Birthdate != nil {
		birthdate, err = parseBirthdate(req.Birthdate)
		if err != nil {
			return uuid.Nil, err
		}
	}

	var issuedDate *string
	if req.IssuedDate != nil {
		issuedDate, err = parseIssuedDate(req.IssuedDate)
		if err != nil {
			return uuid.Nil, err
		}
	}

	profileData.Birthdate = birthdate
	profileData.IssuedDate = issuedDate

	var userID uuid.UUID

	var user *entity.User

	if req.UserID != nil {
		userID = *req.UserID

		user, err = h.s.GetUserByID(ctx, userID)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		if err := service.ValidateSberIDs(req.Sub, req.SubAlt); err != nil {
			return uuid.Nil, err
		}

		user, err = h.s.SearchUser(ctx, req.Email, req.Sub, req.SubAlt)
		if err != nil {
			return uuid.Nil, err
		}

		userID = user.UserID

		sberData := &service.SberIDData{
			Sub:                   req.Sub,
			SubAlt:                req.SubAlt,
			Email:                 req.Email,
			Phone:                 req.Phone,
			LastName:              req.LastName,
			FirstName:             req.FirstName,
			MiddleName:            req.MiddleName,
			Birthdate:             birthdate,
			PrivacyPolicyAgreed:   req.PrivacyPolicyAgreed != nil && *req.PrivacyPolicyAgreed,
			NewsletterAgreed:      req.NewsletterAgreed != nil && *req.NewsletterAgreed,
			PublicDonationsAgreed: req.PublicDonationsAgreed != nil && *req.PublicDonationsAgreed,
		}

		if err := h.s.MergeUserData(ctx, userID, sberData); err != nil {
			return uuid.Nil, err
		}
	}

	hasProfileFields := profileData.LastName != nil || profileData.FirstName != nil ||
		profileData.MiddleName != nil || profileData.Phone != nil ||
		profileData.Birthdate != nil || profileData.City != nil ||
		profileData.SchoolName != nil || profileData.PlaceOfEducation != nil ||
		profileData.AddressReg != nil || profileData.Series != nil ||
		profileData.Number != nil || profileData.IssuedBy != nil ||
		profileData.IssuedDate != nil || profileData.Code != nil ||
		profileData.PersonalInfo != nil

	if hasProfileFields {
		if err := h.s.UpdateUserProfileInternal(ctx, userID, profileData); err != nil {
			return uuid.Nil, err
		}
	}

	if req.Email != nil && !strings.EqualFold(user.Email, *req.Email) {
		if err := h.s.UpdateUserEmail(ctx, userID, *req.Email); err != nil {
			return uuid.Nil, err
		}
	}

	return userID, nil
}

func normalizeStringPtr(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

func normalizeDate(dateStr *string) *string {
	if dateStr == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*dateStr)
	if trimmed == "" {
		return nil
	}

	t, err := time.Parse("2006-01-02", trimmed)
	if err == nil {
		normalized := t.Format("02.01.2006")
		return &normalized
	}

	t, err = time.Parse("2006.01.02", trimmed)
	if err == nil {
		normalized := t.Format("02.01.2006")
		return &normalized
	}

	t, err = time.Parse("02.01.2006", trimmed)
	if err == nil {
		normalized := t.Format("02.01.2006")
		return &normalized
	}

	return &trimmed
}

func parseBirthdate(birthdate *string) (*string, error) {
	normalized := normalizeDate(birthdate)
	if normalized == nil {
		return nil, nil //nolint:nilnil
	}

	_, err := time.Parse("02.01.2006", *normalized)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: некорректный формат даты рождения (ожидается ДД.ММ.ГГГГ, ГГГГ-ММ-ДД или ГГГГ.ММ.ДД)",
			entity.ErrInvalidBirthdate,
		)
	}

	return normalized, nil
}

func parseIssuedDate(issuedDate *string) (*string, error) {
	normalized := normalizeDate(issuedDate)
	if normalized == nil {
		return nil, nil //nolint:nilnil
	}

	_, err := time.Parse("02.01.2006", *normalized)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: некорректный формат даты выдачи паспорта (ожидается ДД.ММ.ГГГГ, ГГГГ-ММ-ДД или ГГГГ.ММ.ДД)",
			entity.ErrInvalidIssuedDate,
		)
	}

	return normalized, nil
}

//nolint:funlen
func handleUserError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, entity.ErrPermissionDenied):
		sendErr(ctx, w, http.StatusForbidden, err, "Доступ запрещён")
	case errors.Is(err, entity.ErrForbidden):
		sendErr(ctx, w, http.StatusForbidden, err, "Доступ запрещён")
	case errors.Is(err, entity.ErrUserBlocked):
		sendErr(ctx, w, http.StatusForbidden, err, "Пользователь заблокирован")
	case errors.Is(err, entity.ErrUserDeleted):
		sendErr(ctx, w, http.StatusForbidden, err, "Пользователь удалён")
	case errors.Is(err, entity.ErrDuplicateEmail):
		sendErr(ctx, w, http.StatusConflict, err, entity.ErrMsgEmailTaken)
	case errors.Is(err, entity.ErrDuplicateSub):
		sendErr(ctx, w, http.StatusConflict, err, entity.ErrMsgSubTaken)
	case errors.Is(err, entity.ErrDuplicateSubAlt):
		sendErr(ctx, w, http.StatusConflict, err, entity.ErrMsgSubAltTaken)
	case errors.Is(err, entity.ErrInvalidEmail):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidPhone):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidBirthdate):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidName):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidCity):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidSchoolName):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidPlaceOfEducation):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidAddress):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidPassportSeries):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidPassportNumber):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidPassportCode):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidIssuedDate):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrInvalidTextField):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrValidationFailed):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrMissingRequiredField):
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
	case errors.Is(err, entity.ErrPrivacyPolicyRequired):
		sendErr(ctx, w, http.StatusBadRequest, err, "Необходимо согласие с политикой конфиденциальности")
	case errors.Is(err, entity.ErrUserNotFound):
		sendErr(ctx, w, http.StatusNotFound, err, entity.ErrMsgNotFound)
	default:
		sendErr(ctx, w, http.StatusInternalServerError, err, entity.ErrMsgInternal)
	}
}

func (h *Handler) createUserBySberID(ctx context.Context, w http.ResponseWriter, rawRequest map[string]interface{}) (uuid.UUID, error) {
	var req CreateUserRequest

	data, err := json.Marshal(rawRequest)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgBadRequest)
		return uuid.Nil, err
	}

	if err := json.Unmarshal(data, &req); err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgBadRequest)
		return uuid.Nil, err
	}

	req.Sub = normalizeStringPtr(req.Sub)
	req.SubAlt = normalizeStringPtr(req.SubAlt)
	req.Phone = normalizeStringPtr(req.Phone)
	req.MiddleName = normalizeStringPtr(req.MiddleName)
	req.Birthdate = normalizeDate(req.Birthdate)
	req.City = normalizeStringPtr(req.City)
	req.SchoolName = normalizeStringPtr(req.SchoolName)
	req.PlaceOfEducation = normalizeStringPtr(req.PlaceOfEducation)
	req.AddressReg = normalizeStringPtr(req.AddressReg)
	req.Series = normalizeStringPtr(req.Series)
	req.Number = normalizeStringPtr(req.Number)
	req.IssuedBy = normalizeStringPtr(req.IssuedBy)
	req.IssuedDate = normalizeDate(req.IssuedDate)
	req.Code = normalizeStringPtr(req.Code)
	req.PersonalInfo = normalizeStringPtr(req.PersonalInfo)

	if req.FirstName == "" {
		sendErr(ctx, w, http.StatusUnprocessableEntity, nil, entity.ErrMsgInvalidData)
		return uuid.Nil, entity.ErrMissingRequiredField
	}

	if req.LastName == "" {
		sendErr(ctx, w, http.StatusUnprocessableEntity, nil, entity.ErrMsgInvalidData)
		return uuid.Nil, entity.ErrMissingRequiredField
	}

	if err := service.ValidateSberIDs(req.Sub, req.SubAlt); err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, entity.ErrMsgInvalidData)
		return uuid.Nil, err
	}

	birthdate, err := parseBirthdate(req.Birthdate)
	if err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, getValidationMessage(err))
		return uuid.Nil, err
	}

	if !req.PrivacyPolicyAgreed {
		sendErr(ctx, w, http.StatusBadRequest, entity.ErrPrivacyPolicyRequired, "Необходимо согласие с политикой конфиденциальности")
		return uuid.Nil, entity.ErrPrivacyPolicyRequired
	}

	sberData := &service.SberIDData{
		Sub:                   req.Sub,
		SubAlt:                req.SubAlt,
		Email:                 &req.Email,
		Phone:                 req.Phone,
		LastName:              &req.LastName,
		FirstName:             &req.FirstName,
		MiddleName:            req.MiddleName,
		Birthdate:             birthdate,
		PrivacyPolicyAgreed:   req.PrivacyPolicyAgreed,
		NewsletterAgreed:      req.NewsletterAgreed,
		PublicDonationsAgreed: req.PublicDonationsAgreed,
	}

	return h.s.CreateUserBySberID(ctx, sberData)
}

func (h *Handler) createUserByEmail(ctx context.Context, w http.ResponseWriter, rawRequest map[string]interface{}) (uuid.UUID, error) {
	var req CreateUserRequest

	data, err := json.Marshal(rawRequest)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgBadRequest)
		return uuid.Nil, err
	}

	if err := json.Unmarshal(data, &req); err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, entity.ErrMsgBadRequest)
		return uuid.Nil, err
	}

	if !req.PrivacyPolicyAgreed {
		sendErr(ctx, w, http.StatusBadRequest, entity.ErrPrivacyPolicyRequired, "Необходимо согласие с политикой конфиденциальности")
		return uuid.Nil, entity.ErrPrivacyPolicyRequired
	}

	return h.s.CreateUserByEmail(
		ctx, req.Email, req.FirstName, req.LastName,
		req.PrivacyPolicyAgreed, req.NewsletterAgreed, req.PublicDonationsAgreed,
	)
}

type SearchUserRequest struct {
	Email  *string `json:"email,omitempty"`
	Sub    *string `json:"sub,omitempty"`
	SubAlt *string `json:"sub_alt,omitempty"`
}

type SearchUserResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	Status    string    `json:"status"`
	Email     string    `json:"email"`
	RoleID    uuid.UUID `json:"role_id"`
	RoleName  string    `json:"role_name"`
	BlockType *string   `json:"block_type,omitempty"`
}

type GetUserResponse struct {
	UserID             uuid.UUID `json:"user_id"`
	Email              string    `json:"email"`
	FirstName          *string   `json:"first_name,omitempty"`
	LastName           *string   `json:"last_name,omitempty"`
	MiddleName         *string   `json:"middle_name,omitempty"`
	Phone              *string   `json:"phone,omitempty"`
	Birthdate          *string   `json:"birthdate,omitempty"`
	Status             string    `json:"status"`
	VerificationStatus *string   `json:"verification_status,omitempty"` // Только для admin
	RoleID             uuid.UUID `json:"role_id"`
	RoleName           string    `json:"role_name"`
	City               *string   `json:"city,omitempty"`
	SchoolName         *string   `json:"school_name,omitempty"`
	PlaceOfEducation   *string   `json:"place_of_education,omitempty"`
	AddressReg         *string   `json:"address_reg,omitempty"`
}

type GetUserByIDResponse struct {
	UserID     uuid.UUID `json:"user_id"`
	LastName   *string   `json:"last_name,omitempty"`
	FirstName  *string   `json:"first_name,omitempty"`
	MiddleName *string   `json:"middle_name,omitempty"`
	Email      string    `json:"email"`
	Phone      *string   `json:"phone,omitempty"`
	Birthdate  *string   `json:"birthdate,omitempty"`
	RoleID     uuid.UUID `json:"role_id"`
	RoleName   string    `json:"role_name"`
}

type GetUserProfileResponse struct {
	UserID                uuid.UUID `json:"user_id"`
	LastName              *string   `json:"last_name,omitempty"`
	FirstName             *string   `json:"first_name,omitempty"`
	MiddleName            *string   `json:"middle_name,omitempty"`
	Email                 string    `json:"email"`
	Phone                 *string   `json:"phone,omitempty"`
	Birthdate             *string   `json:"birthdate,omitempty"`
	City                  *string   `json:"city,omitempty"`
	SchoolName            *string   `json:"school_name,omitempty"`
	PlaceOfEducation      *string   `json:"place_of_education,omitempty"`
	AddressReg            *string   `json:"address_reg,omitempty"`
	Series                *string   `json:"series,omitempty"`
	Number                *string   `json:"number,omitempty"`
	IssuedBy              *string   `json:"issued_by,omitempty"`
	IssuedDate            *string   `json:"issued_date,omitempty"`
	Code                  *string   `json:"code,omitempty"`
	PersonalInfo          *string   `json:"personal_info,omitempty"`
	PrivacyPolicyAgreed   bool      `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool      `json:"newsletter_agreed"`
	PublicDonationsAgreed bool      `json:"public_donations_agreed"`
}

type EmptyResponse struct{}

// @Summary Поиск пользователя
// @Description Поиск пользователя по email, sub или sub_alt
// @Tags users
// @Accept json
// @Produce json
// @Param email query string false "Email пользователя"
// @Param sub query string false "Сбер ID (sub)"
// @Param sub_alt query string false "Альтернативный Сбер ID (sub_alt)"
// @Success 200 {object} SearchUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /internal/users [get]
func (h *Handler) SearchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	email, sub, subAlt, err := parseSearchUserParams(r.URL.Query())
	if err != nil {
		slog.WarnContext(ctx, "Invalid search parameters", "error", err)
		sendErr(ctx, w, http.StatusBadRequest, err, err.Error())
		return
	}

	user, err := h.s.SearchUser(ctx, email, sub, subAlt)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			slog.InfoContext(ctx, "User not found in search",
				"email", email, "sub", sub, "sub_alt", subAlt)
			sendErr(ctx, w, http.StatusNotFound, err, "user not found")
		case errors.Is(err, entity.ErrUserBlocked):
			slog.WarnContext(ctx, "Blocked user search attempt", "email", email)
			sendErr(ctx, w, http.StatusForbidden, err, "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку")
		case errors.Is(err, entity.ErrUserDeleted):
			slog.WarnContext(ctx, "Deleted user search attempt", "email", email)
			sendErr(ctx, w, http.StatusGone, err, "Аккаунт удалён. Для восстановления обратитесь в поддержку.")
		default:
			slog.ErrorContext(ctx, "Failed to search user", "error", err)
			sendErr(ctx, w, http.StatusInternalServerError, err, "internal server error")
		}

		return
	}

	slog.InfoContext(ctx, "User found successfully",
		"user_id", user.UserID, "email", user.Email, "status", user.Status, "role_id", user.RoleID)

	response := SearchUserResponse{
		UserID: user.UserID,
		Status: string(user.Status),
		Email:  user.Email,
		RoleID: user.RoleID,
	}

	role, err := h.s.GetUserRole(ctx, user.UserID)
	if err == nil && role != nil {
		response.RoleName = role.Name
	}

	if user.Status == entity.UserStatusBlocked {
		block, err := h.s.GetUserBlock(ctx, user.UserID)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to get user block info",
				"user_id", user.UserID, "error", err)
		} else if block != nil && block.BlockType != nil {
			response.BlockType = (*string)(block.BlockType)
		}
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

// @Summary Получение собственного профиля
// @Description Получить полные данные профиля авторизованного пользователя
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} GetUserProfileResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /users/me [get]
func (h *Handler) GetUserMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	user, err := entity.UserFromContext(ctx)
	if err != nil {
		slog.WarnContext(ctx, "GetUserProfile: user not in context", "error", err)
		sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)

		return
	}

	slog.DebugContext(ctx, "GetUserProfile: start", "user_id", user.UserID)

	userProfile, err := h.s.GetUserProfile(ctx, user.UserID)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			slog.WarnContext(ctx, "GetUserProfile: user not found", "user_id", user.UserID)
			sendErr(ctx, w, http.StatusNotFound, err, "user not found")
		default:
			slog.ErrorContext(ctx, "GetUserProfile: failed", "error", err)
			sendErr(ctx, w, http.StatusInternalServerError, err, "internal server error")
		}

		return
	}

	response := GetUserProfileResponse{
		UserID:                userProfile.UserID,
		Email:                 userProfile.Email,
		FirstName:             userProfile.FirstName,
		LastName:              userProfile.LastName,
		MiddleName:            userProfile.MiddleName,
		Phone:                 userProfile.Phone,
		Birthdate:             userProfile.Birthdate,
		City:                  userProfile.City,
		SchoolName:            userProfile.SchoolName,
		PlaceOfEducation:      userProfile.PlaceOfEducation,
		AddressReg:            userProfile.AddressReg,
		Series:                userProfile.Series,
		Number:                userProfile.Number,
		IssuedBy:              userProfile.IssuedBy,
		IssuedDate:            userProfile.IssuedDate,
		Code:                  userProfile.Code,
		PersonalInfo:          userProfile.PersonalInfo,
		PrivacyPolicyAgreed:   userProfile.PrivacyPolicyAgreed,
		NewsletterAgreed:      userProfile.NewsletterAgreed,
		PublicDonationsAgreed: userProfile.PublicDonationsAgreed,
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

// @Summary Получение профиля пользователя
// @Description Получить полные данные профиля пользователя по ID
// @Tags users
// @Accept json
// @Produce json
// @Param user_id path string true "ID пользователя"
// @Success 200 {object} GetUserByIDResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /internal/users/{user_id} [get]
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDStr := r.PathValue("user_id")
	if userIDStr == "" {
		sendErr(ctx, w, http.StatusBadRequest, nil, "user_id is required")
		return
	}

	userID, err := parseGetUserParams(userIDStr)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, err.Error())
		return
	}

	user, err := h.s.GetUserByID(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			sendErr(ctx, w, http.StatusNotFound, err, "user not found")
		default:
			sendErr(ctx, w, http.StatusInternalServerError, err, "internal server error")
		}

		return
	}

	var roleName string

	role, err := h.s.GetUserRole(ctx, user.UserID)
	if err != nil {
		slog.WarnContext(ctx, "Failed to get user role",
			"user_id", user.UserID, "error", err)
	} else if role != nil {
		roleName = role.Name
	}

	response := GetUserByIDResponse{
		UserID:     user.UserID,
		Email:      user.Email,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		MiddleName: user.MiddleName,
		Phone:      user.Phone,
		Birthdate:  user.Birthdate,
		RoleID:     user.RoleID,
		RoleName:   roleName,
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

type BlockUserRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

type BlockUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
	Status string    `json:"status"`
}

type TemporaryBlockUserRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

type TemporaryBlockUserResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	Status    string    `json:"status"`
	BlockType *int      `json:"block_type,omitempty"`
	ExpiresAt *string   `json:"expires_at,omitempty"`
}

// @Summary Заблокировать пользователя
// @Description Блокировка пользователя на время или на постоянно (только для служб безопасности)
// @Tags security
// @Accept json
// @Produce json
// @Security SecurityToken
// @Param request body BlockUserRequest true "Запрос на блокировку"
// @Success 200 {object} BlockUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Router /users/block [post]
func (h *Handler) BlockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	slog.InfoContext(ctx, "BlockUser request received",
		"method", r.Method,
		"url", r.URL.Path,
		"remote_addr", r.RemoteAddr,
	)

	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	slog.InfoContext(ctx, "BlockUser request body",
		"body", string(bodyBytes),
	)

	var req BlockUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.ErrorContext(ctx, "Failed to decode BlockUser request",
			"error", err,
			"body", string(bodyBytes),
		)
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")

		return
	}

	slog.InfoContext(ctx, "BlockUser request parsed",
		"user_id", req.UserID,
	)

	slog.InfoContext(ctx, "Block requested by security service",
		"user_id", req.UserID,
	)

	err := h.s.BlockUserBySecurity(ctx, req.UserID, nil)
	if err != nil {
		if errors.Is(err, entity.ErrTokenDestroyFailed) {
			slog.WarnContext(ctx, "User blocked but failed to destroy tokens",
				"user_id", req.UserID,
				"error", err,
			)
		} else {
			slog.ErrorContext(ctx, "Failed to block user",
				"user_id", req.UserID,
				"error", err,
			)

			switch {
			case errors.Is(err, entity.ErrUserNotFound):
				sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
			case errors.Is(err, entity.ErrUserAlreadyBlocked):
				sendErr(ctx, w, http.StatusConflict, err, "Пользователь уже заблокирован")
			case errors.Is(err, entity.ErrInvalidStatus):
				sendErr(ctx, w, http.StatusUnprocessableEntity, err, "Невалидный статус")
			default:
				sendErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка сервера")
			}

			return
		}
	}

	slog.InfoContext(ctx, "User blocked successfully (permanent)",
		"user_id", req.UserID,
	)

	response := BlockUserResponse{
		UserID: req.UserID,
		Status: "blocked",
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

// @Summary Временная блокировка пользователя (internal)
// @Description Временная блокировка пользователя для внутренних сервисов
// @Tags internal
// @Accept json
// @Produce json
// @Param request body TemporaryBlockUserRequest true "Запрос на временную блокировку"
// @Success 200 {object} TemporaryBlockUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /internal/users/temporary-block [post]
func (h *Handler) BlockUserInternal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req TemporaryBlockUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.ErrorContext(ctx, "Failed to decode temporary block request", "error", err)
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")

		return
	}

	err := h.s.BlockUserInternal(ctx, req.UserID, nil)
	if err != nil {
		if errors.Is(err, entity.ErrTokenDestroyFailed) {
			slog.WarnContext(ctx, "User blocked but failed to destroy tokens",
				"user_id", req.UserID,
				"error", err,
			)
		} else {
			switch {
			case errors.Is(err, entity.ErrUserNotFound):
				sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
			case errors.Is(err, entity.ErrUserAlreadyBlocked):
				sendErr(ctx, w, http.StatusConflict, err, "Пользователь уже заблокирован")
			case errors.Is(err, entity.ErrInvalidStatus):
				sendErr(ctx, w, http.StatusUnprocessableEntity, err, "Невалидный статус")
			default:
				sendErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка сервера")
			}

			return
		}
	}

	block, err := h.s.GetUserBlock(ctx, req.UserID)
	if err != nil {
		slog.WarnContext(ctx, "Failed to get block info", "error", err)
	}

	response := TemporaryBlockUserResponse{
		UserID: req.UserID,
		Status: "blocked",
	}

	if block != nil {
		if block.BlockType != nil {
			var blockTypeInt int
			if *block.BlockType == entity.BlockTypeTemporary {
				blockTypeInt = 1
			} else {
				blockTypeInt = 0
			}

			response.BlockType = &blockTypeInt
		}

		if block.BlockedTo != nil {
			expiresAt := block.BlockedTo.Format(time.RFC3339)
			response.ExpiresAt = &expiresAt
		}
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

type UnblockUserRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

type UnblockUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
	Status string    `json:"status"`
}

// @Summary Разблокировать пользователя
// @Description Разблокировка постоянно заблокированного пользователя (только для служб безопасности)
// @Tags security
// @Accept json
// @Produce json
// @Security SecurityToken
// @Param request body UnblockUserRequest true "Запрос на разблокировку"
// @Success 200 {object} UnblockUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Router /users/unblock [post]
func (h *Handler) UnblockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := parseUserIDFromRequest(r)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	slog.InfoContext(ctx, "Unblock requested by security service",
		"user_id", userID,
	)

	err = h.s.UnblockUserBySecurity(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
		case errors.Is(err, entity.ErrUserAlreadyActive):
			sendErr(ctx, w, http.StatusConflict, err, "Пользователь уже активен")
		case errors.Is(err, entity.ErrCannotUnblockTemporary):
			sendErr(ctx, w, http.StatusUnprocessableEntity, err, "Нельзя разблокировать временную блокировку")
		default:
			sendErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка сервера")
		}

		return
	}

	response := UnblockUserResponse{
		UserID: userID,
		Status: "active",
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

type DeleteUserResponse struct {
	Message string `json:"message"`
}

// @Summary Удалить аккаунт пользователя
// @Description Мягкое удаление собственного аккаунта
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} DeleteUserResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /users/me [delete]
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "user_action")

	user, err := entity.UserFromContext(ctx)
	if err != nil {
		sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)
		return
	}

	accessToken := extractTokenFromHeader(r)

	err = h.s.MarkAsDeleted(ctx, user.UserID, accessToken)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
		default:
			sendErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка сервера")
		}

		return
	}

	slog.InfoContext(ctx, "User account deleted", "user_id", user.UserID, "action", "delete")

	response := DeleteUserResponse{
		Message: "Аккаунт удалён",
	}

	sendJSON(ctx, w, http.StatusOK, response)
}

type RestoreUserRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

type RestoreUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
	Status string    `json:"status"`
}

// @Summary Восстановить удалённый аккаунт
// @Description Восстановление удалённого аккаунта по user_id (без авторизации)
// @Tags users
// @Accept json
// @Produce json
// @Param request body RestoreUserRequest true "User ID для восстановления"
// @Success 200 {object} RestoreUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 410 {object} ErrorResponse "Период восстановления истёк"
// @Failure 422 {object} ErrorResponse "Невалидный статус пользователя"
// @Router /internal/users/restore [post]
func (h *Handler) RestoreUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "user_action")

	var req RestoreUserRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Невалидный формат запроса")
		return
	}

	if err := h.s.RestoreUserByID(ctx, req.UserID); err != nil {
		switch {
		case errors.Is(err, entity.ErrUserNotFound):
			sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
		case errors.Is(err, entity.ErrRestorePeriodExpired):
			sendErr(ctx, w, http.StatusGone, err, "Период восстановления истёк")
		case errors.Is(err, entity.ErrInvalidStatus):
			sendErr(ctx, w, http.StatusUnprocessableEntity, err, "Невалидный статус пользователя")
		default:
			sendErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка сервера")
		}

		return
	}

	slog.InfoContext(ctx, "User account restored", "user_id", req.UserID, "action", "restore")

	response := RestoreUserResponse{
		UserID: req.UserID,
		Status: "active",
	}

	sendJSON(ctx, w, http.StatusOK, response)
}
