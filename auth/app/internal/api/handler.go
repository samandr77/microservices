package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/internal/service"
	"github.com/samandr77/microservices/auth/pkg/logger"
)

type Service interface {
	SendSignupCode(
		ctx context.Context, email, firstName, lastName string,
		privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
	) error
	SendAuthCode(ctx context.Context, email string) error
	CheckCode(ctx context.Context, email, code string, action entity.VerificationAction) error
	Authenticate(ctx context.Context, email, code string) (*entity.UserTokens, error)
	RefreshToken(ctx context.Context, refreshToken string) (*entity.UserTokens, error)
	ValidateToken(ctx context.Context, accessToken string) (*entity.User, error)
	RevokeToken(ctx context.Context, userID uuid.UUID) error
	Signing(ctx context.Context, email, code string) (entity.UserTokens, error)
	SigningAuth(ctx context.Context, email, code string) (entity.UserTokens, error)
	SigningRegister(ctx context.Context, email, code, firstName, lastName string) (entity.UserTokens, error)
	RegisterWithSberID(
		ctx context.Context, code string,
		privacyPolicyAgreed, newsletterAgreed, publicDonationsAgreed bool,
	) (*entity.UserTokens, error)
	UpdateEmailAndAuthorize(ctx context.Context, userID uuid.UUID, email string) (*entity.UserTokens, error)
}

type Handler struct {
	s                 Service
	supportLink       string
	sberIDClientID    string
	sberIDRedirectURI string
	sberIDScope       string
	sberIDBaseURL     string
}

func NewHandler(s Service, supportLink, sberIDClientID, sberIDRedirectURI, sberIDScope, sberIDBaseURL string) *Handler {
	return &Handler{
		s:                 s,
		supportLink:       supportLink,
		sberIDClientID:    sberIDClientID,
		sberIDRedirectURI: sberIDRedirectURI,
		sberIDScope:       sberIDScope,
		sberIDBaseURL:     sberIDBaseURL,
	}
}

// @Summary Проверка состояния сервиса
// @Description Проверяет, что сервер работает
// @Tags auth
// @Accept  json
// @Produce  json
// @Success 200 {string} string "Сервер работает!"
// @Router  /api/health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Сервер работает!\n"))
}

type SendCodeRequest struct {
	Email                 string `json:"email"`
	FirstName             string `json:"first_name,omitempty"`
	LastName              string `json:"last_name,omitempty"`
	PrivacyPolicyAgreed   *bool  `json:"privacy_policy_agreed,omitempty"`
	NewsletterAgreed      *bool  `json:"newsletter_agreed,omitempty"`
	PublicDonationsAgreed *bool  `json:"public_donations_agreed,omitempty"`
}

type SendCodeResponse struct {
	Message string `json:"message"`
}

func (h *Handler) validateRegistrationRequest(
	ctx context.Context, w http.ResponseWriter, req SendCodeRequest,
) (privacyAgreed, newsletterAgreed, publicDonationsAgreed bool, ok bool) {
	if err := service.ValidateName(req.FirstName); err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, nameErrRuText(err))
		return false, false, false, false
	}

	if err := service.ValidateName(req.LastName); err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, nameErrRuText(err))
		return false, false, false, false
	}

	if req.PrivacyPolicyAgreed == nil || !*req.PrivacyPolicyAgreed {
		sendErr(
			ctx, w, http.StatusBadRequest,
			errors.New("privacy policy agreement required"),
			"Необходимо согласие с политикой конфиденциальности",
		)

		return false, false, false, false
	}

	newsletter := false
	if req.NewsletterAgreed != nil {
		newsletter = *req.NewsletterAgreed
	}

	publicDonations := false
	if req.PublicDonationsAgreed != nil {
		publicDonations = *req.PublicDonationsAgreed
	}

	return *req.PrivacyPolicyAgreed, newsletter, publicDonations, true
}

// @Summary Отправить код подтверждения
// @Description Отправка кода подтверждения на email. Если переданы first_name и last_name - это регистрация, иначе - авторизация.
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body SendCodeRequest true "Email для отправки кода (и опционально имя/фамилия для регистрации)"
// @Success 200 {object} SendCodeResponse "Код отправлен"
// @Failure 400 {object} ResponseError "Некорректный запрос"
// @Failure 404 {object} ResponseError "Пользователь не найден"
// @Failure 410 {object} ResponseError "Аккаунт удалён"
// @Failure 423 {object} ResponseError "Блокировка"
// @Failure 429 {object} ResponseError "Слишком много запросов"
// @Failure 500 {object} ResponseError "Не удалось отправить код"
// @Router  /api/code/send [post]
func (h *Handler) SendCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "auth")

	var req SendCodeRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	err = service.ValidateEmail(req.Email)
	if err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, emailErrRuText(err))
		return
	}

	isRegistration := req.FirstName != "" && req.LastName != ""

	if isRegistration {
		privacyAgreed, newsletterAgreed, publicDonationsAgreed, ok := h.validateRegistrationRequest(ctx, w, req)
		if !ok {
			return
		}

		err = h.s.SendSignupCode(ctx, req.Email, req.FirstName, req.LastName, privacyAgreed, newsletterAgreed, publicDonationsAgreed)
	} else {
		err = h.s.SendAuthCode(ctx, req.Email)
	}

	if err != nil {
		var be *entity.BlockedError
		if errors.As(err, &be) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message:   "Слишком много попыток. Попробуйте позже.",
				BlockedTo: be.BlockedTo,
			})

			return
		}

		if errors.Is(err, entity.ErrNotFound) {
			sendErr(ctx, w, http.StatusNotFound, err, "Пользователь с таким email не найден. Зарегистрируйтесь, чтобы продолжить.")

			return
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message: "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку",
			})

			return
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			sendErr(ctx, w, http.StatusGone, err, "Аккаунт удалён. Для восстановления обратитесь в поддержку.")

			return
		}

		if errors.Is(err, entity.ErrAttemptTimerNotExpired) {
			sendErr(ctx, w, http.StatusLocked, err, "Слишком много попыток. Попробуйте позже.")

			return
		}

		if errors.Is(err, entity.ErrManyAttempts) {
			sendErr(ctx, w, http.StatusTooManyRequests, err, "Слишком много запросов. Попробуйте позже")

			return
		}

		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось отправить код")

		return
	}

	resp := SendCodeResponse{
		Message: "Код отправлен",
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type CheckCodeRequest struct {
	Email string `json:"email"`
	OTP   string `json:"OTP"`
}

type CheckCodeResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// @Summary Проверить код подтверждения
// @Description Проверка кода подтверждения для авторизации. Возвращает access token.
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body CheckCodeRequest true "Email и код для проверки"
// @Success 200 {object} CheckCodeResponse "Токен успешно получен"
// @Failure 401 {object} ResponseError "Неверный или просроченный код"
// @Failure 423 {object} ResponseError "Блокировка"
// @Failure 429 {object} ResponseError "Слишком много попыток"
// @Failure 500 {object} ResponseError "Не удалось проверить код"
// @Router  /api/code/check [post]
func (h *Handler) CheckCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "auth")

	var req CheckCodeRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	tokens, err := h.s.Signing(ctx, req.Email, req.OTP)
	if err != nil {
		var be *entity.BlockedError
		if errors.As(err, &be) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message:   "Слишком много попыток. Попробуйте позже.",
				BlockedTo: be.BlockedTo,
			})

			return
		}

		if errors.Is(err, entity.ErrCodeInvalid) {
			sendErr(ctx, w, http.StatusUnauthorized, err, "Неверный код")

			return
		}

		if errors.Is(err, entity.ErrCodeExpired) {
			sendErr(ctx, w, http.StatusUnauthorized, err, "Неверный или просроченный код")

			return
		}

		if errors.Is(err, entity.ErrNotFound) {
			sendErr(ctx, w, http.StatusUnauthorized, err, "Неверный или просроченный код")

			return
		}

		if errors.Is(err, entity.ErrManyAttempts) {
			sendErr(ctx, w, http.StatusTooManyRequests, err, "Слишком много попыток. Попробуйте позже")

			return
		}

		if errors.Is(err, entity.ErrAttemptTimerNotExpired) {
			sendErr(ctx, w, http.StatusLocked, err, "Слишком много попыток. Попробуйте позже.")

			return
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message: "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку",
			})

			return
		}

		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось проверить код")

		return
	}

	resp := CheckCodeResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type ValidateTokenRequest struct {
	AccessToken string `json:"access_token"`
}

type ValidateTokenResponse struct {
	UserID string `json:"user_id"`
}

// @Summary Валидация токена авторизации
// @Description Проверка валидности access token и получение user_id
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body ValidateTokenRequest true "Access token для валидации"
// @Success 200 {object} ValidateTokenResponse "Токен валиден"
// @Failure 401 {object} ResponseError "Токен невалидный"
// @Failure 500 {object} ResponseError "Не удалось проверить токен"
// @Router  /api/token/validate [post]
func (h *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "token")

	var req ValidateTokenRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.AccessToken == "" {
		sendErr(ctx, w, http.StatusUnauthorized, errors.New("access token not provided"), "Токен не передан")
		return
	}

	user, err := h.s.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		if errors.Is(err, entity.ErrUserBlocked) {
			sendErr(ctx, w, http.StatusForbidden, err, "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку")
			return
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			sendErr(ctx, w, http.StatusGone, err, "Аккаунт удалён. Для восстановления обратитесь в поддержку.")
			return
		}

		sendErr(ctx, w, http.StatusUnauthorized, err, "Токен невалидный")

		return
	}

	resp := ValidateTokenResponse{
		UserID: user.ID.String(),
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type DestroyTokenRequest struct {
	SessionToken string `json:"session_token"`
}

type DestroyTokenResponse struct {
	Message string `json:"message"`
}

type DestroyTokenInternalRequest struct {
	UserID string `json:"user_id"`
}

type DestroyTokenInternalResponse struct {
	Message string `json:"message"`
}

// @Summary Удаление/инвалидация токена авторизации
// @Description Удаляет refresh token пользователя, делая его сессию невалидной
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body DestroyTokenRequest true "Session token (access token) для определения пользователя"
// @Success 200 {object} DestroyTokenResponse "Токен успешно удален"
// @Failure 401 {object} ResponseError "Токен невалидный"
// @Failure 500 {object} ResponseError "Не удалось удалить токен"
// @Router  /api/token/destroy [post]
func (h *Handler) DestroyToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "token")

	var req DestroyTokenRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.SessionToken == "" {
		sendErr(ctx, w, http.StatusUnauthorized, errors.New("session token not provided"), "Токен не передан")
		return
	}

	user, err := h.s.ValidateToken(ctx, req.SessionToken)
	if err != nil {
		sendErr(ctx, w, http.StatusUnauthorized, err, "Токен невалидный")
		return
	}

	err = h.s.RevokeToken(ctx, user.ID)
	if err != nil {
		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось удалить токен")
		return
	}

	resp := DestroyTokenResponse{
		Message: "Токен успешно удален",
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

// @Summary Удаление токенов пользователя (internal)
// @Description Internal endpoint для межсервисного взаимодействия. Удаляет все refresh токены пользователя по его ID
// @Tags internal
// @Accept  json
// @Produce  json
// @Param   request body DestroyTokenInternalRequest true "User ID для удаления токенов"
// @Success 200 {object} DestroyTokenInternalResponse "Токены успешно удалены"
// @Failure 400 {object} ResponseError "Некорректный запрос или невалидный UUID"
// @Failure 500 {object} ResponseError "Не удалось удалить токены"
// @Router  /internal/api/token/destroy [post]
func (h *Handler) DestroyTokenInternal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "token")

	var req DestroyTokenInternalRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.UserID == "" {
		sendErr(ctx, w, http.StatusBadRequest, errors.New("user_id not provided"), "User ID не передан")
		return
	}

	userID, err := uuid.FromString(req.UserID)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный формат User ID")
		return
	}

	err = h.s.RevokeToken(ctx, userID)
	if err != nil {
		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось удалить токены")
		return
	}

	resp := DestroyTokenInternalResponse{
		Message: "Токены успешно удалены",
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken string `json:"accessToken"`
	Message     string `json:"message"`
}

// @Summary Обновление токена авторизации
// @Description Обновляет access token используя refresh token
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body RefreshTokenRequest true "Refresh token для обновления"
// @Success 200 {object} RefreshTokenResponse "Токены успешно обновлены"
// @Failure 401 {object} ResponseError "Токен обновления не передан"
// @Failure 500 {object} ResponseError "Не удалось обновить токен"
// @Router  /api/token/refresh [post]
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "token")

	var req RefreshTokenRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.RefreshToken == "" {
		sendErr(ctx, w, http.StatusUnauthorized, errors.New("refresh token not provided"), "Токен обновления не передан")
		return
	}

	tokens, err := h.s.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			sendErr(ctx, w, http.StatusUnauthorized, err, "Токен обновления недействителен")
			return
		}

		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось обновить токен")

		return
	}

	resp := RefreshTokenResponse{
		AccessToken: tokens.AccessToken,
		Message:     "Токены успешно обновлены",
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type OpenIDCodeRequest struct {
	Code string `json:"code"`
}

type OpenIDCodeResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// @Summary Получение кода авторизации от OpenID провайдера (Sber ID)
// @Description Обмен кода авторизации на токены и регистрация/привязка пользователя
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   request body OpenIDCodeRequest true "Код авторизации от Sber ID"
// @Success 200 {object} OpenIDCodeResponse "Успешная регистрация/авторизация"
// @Failure 400 {object} ResponseError "Некорректный запрос"
// @Failure 401 {object} ResponseError "Неверный код авторизации"
// @Failure 410 {object} ResponseError "Аккаунт удалён"
// @Failure 423 {object} ResponseError "Аккаунт заблокирован"
// @Failure 500 {object} ResponseError "Внутренняя ошибка"
// @Router  /api/openid/code [post]
//
//nolint:wsl,whitespace // complex error handling with multiple conditions
func (h *Handler) RegisterWithSberID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "auth")

	var req OpenIDCodeRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.Code == "" {
		sendErr(ctx, w, http.StatusBadRequest, errors.New("code is required"), "Код авторизации обязателен")
		return
	}

	tokens, err := h.s.RegisterWithSberID(ctx, req.Code, true, true, true)
	if err != nil {
		var be *entity.BlockedError
		if errors.As(err, &be) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message:   "Слишком много попыток. Попробуйте позже.",
				BlockedTo: be.BlockedTo,
			})
			return
		}

		var ese *entity.EmailSelectionError
		if errors.As(err, &ese) {
			sendJSON(ctx, w, http.StatusConflict, entity.EmailSelectionRequired{
				Message: "Выберите почту, чтобы продолжить",
				UserID:  ese.UserID,
				Emails:  ese.Emails,
			})
			return
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message: "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку",
			})
			return
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			sendErr(ctx, w, http.StatusGone, err, "Аккаунт удалён. Для восстановления обратитесь в поддержку.")
			return
		}

		if errors.Is(err, entity.ErrSberIDInvalidCode) ||
			errors.Is(err, entity.ErrSberIDCodeExpired) ||
			errors.Is(err, entity.ErrSberIDInvalidClient) ||
			errors.Is(err, entity.ErrSberIDInvalidRequest) ||
			errors.Is(err, entity.ErrSberIDInvalidAccessToken) ||
			errors.Is(err, entity.ErrSberIDAccessTokenExpired) ||
			errors.Is(err, entity.ErrSberIDScopeInsufficient) ||
			errors.Is(err, entity.ErrSberIDRateLimitExceeded) ||
			errors.Is(err, entity.ErrSberIDForbidden) ||
			errors.Is(err, entity.ErrSberIDNotFound) ||
			errors.Is(err, entity.ErrSberIDServiceUnavailable) {
			sendErr(ctx, w, http.StatusBadRequest, err, sberIDErrRuText(err))
			return
		}

		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось зарегистрироваться через Sber ID")
		return
	}

	resp := OpenIDCodeResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}

type SberIDConfigResponse struct {
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	RedirectURI string `json:"redirect_uri"`
	BaseURL     string `json:"base_url"`
}

// @Summary Получить конфигурацию Sber ID
// @Description Возвращает конфигурацию для OAuth авторизации через Sber ID
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} SberIDConfigResponse
// @Router /api/sberid/config [get]
func (h *Handler) GetSberIDConfig(w http.ResponseWriter, r *http.Request) {
	resp := SberIDConfigResponse{
		ClientID:    h.sberIDClientID,
		Scope:       h.sberIDScope,
		RedirectURI: h.sberIDRedirectURI,
		BaseURL:     h.sberIDBaseURL,
	}

	sendJSON(r.Context(), w, http.StatusOK, resp)
}

type UpdateEmailSelectionRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type UpdateEmailSelectionResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// @Summary Обновить email и авторизовать пользователя
// @Description Обновляет email пользователя после выбора и возвращает токены авторизации
// @Tags auth
// @Accept json
// @Produce json
// @Param request body UpdateEmailSelectionRequest true "Выбранный email и идентификаторы Sber ID"
// @Success 200 {object} UpdateEmailSelectionResponse "Успешная авторизация"
// @Failure 400 {object} ResponseError "Некорректный запрос"
// @Failure 401 {object} ResponseError "Сессия истекла"
// @Failure 404 {object} ResponseError "Пользователь не найден"
// @Failure 410 {object} ResponseError "Аккаунт удалён"
// @Failure 423 {object} ResponseError "Аккаунт заблокирован"
// @Failure 500 {object} ResponseError "Внутренняя ошибка"
// @Router /api/email/update [post]
func (h *Handler) UpdateEmailSelection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = logger.SetLogType(ctx, "auth")

	var req UpdateEmailSelectionRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный запрос")
		return
	}

	if req.Email == "" {
		sendErr(ctx, w, http.StatusBadRequest, errors.New("email is required"), "Email обязателен")
		return
	}

	if req.UserID == "" {
		sendErr(ctx, w, http.StatusBadRequest, errors.New("user_id is required"), "User ID обязателен")
		return
	}

	err = service.ValidateEmail(req.Email)
	if err != nil {
		sendErr(ctx, w, http.StatusUnprocessableEntity, err, emailErrRuText(err))
		return
	}

	userID, err := uuid.FromString(req.UserID)
	if err != nil {
		sendErr(ctx, w, http.StatusBadRequest, err, "Некорректный формат user_id")
		return
	}

	tokens, err := h.s.UpdateEmailAndAuthorize(ctx, userID, req.Email)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			sendErr(ctx, w, http.StatusNotFound, err, "Пользователь не найден")
			return
		}

		if errors.Is(err, entity.ErrUserBlocked) {
			sendJSON(ctx, w, http.StatusLocked, ResponseError{
				Message: "Подозрительная активность. Аккаунт заблокирован. Обратитесь в поддержку",
			})

			return
		}

		if errors.Is(err, entity.ErrUserDeleted) {
			sendErr(ctx, w, http.StatusGone, err, "Аккаунт удалён. Для восстановления обратитесь в поддержку.")
			return
		}

		if errors.Is(err, entity.ErrAlreadyExists) {
			sendErr(ctx, w, http.StatusConflict, err, "Email уже занят другим пользователем")
			return
		}

		if errors.Is(err, entity.ErrSberIDInvalidRequest) {
			sendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса")
			return
		}

		sendErr(ctx, w, http.StatusInternalServerError, err, "Не удалось обновить email")

		return
	}

	resp := UpdateEmailSelectionResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	sendJSON(ctx, w, http.StatusOK, resp)
}
