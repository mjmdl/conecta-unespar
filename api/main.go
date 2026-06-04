// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name access-token
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	swagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"

	_ "api/docs"
)

func main() {
	environment := getEnvironmentVariables()
	
	connectionPool, err := pgxpool.New(context.Background(), environment.DatabaseUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer connectionPool.Close()
	
	app := application{
		Environment: environment,
		Database:    connectionPool,
		Validate:    createValidate(),
	}
	
	router := chi.NewRouter()
	app.setupRoutes(router)

	log.Printf("Listening to :%s", environment.ServerPort)
	http.ListenAndServe(":" + environment.ServerPort, router)
}

/*
 * Application
 */

type application struct {
	Environment environmentVariables
	Database    *pgxpool.Pool
	Validate    *validator.Validate
}

func (app *application) setupRoutes(router chi.Router) {
	router.Route("/", func(router chi.Router) {
		if app.Environment.IsDevelopment {
			router.Get("/swagger/*", swagger.WrapHandler)
		}
		router.Post("/logup", app.PostLogup)
		router.Post("/login", app.PostLogin)
		router.Group(func(router chi.Router) {
			router.Use(app.AuthMiddleware)
			router.Post("/logout", app.PostLogout)
			router.Get("/me", app.GetMe)
			router.Get("/attach/{id}", app.GetAttach)
			router.Put("/profile-picture", app.PutProfilePicture)
			router.Delete("/profile-picture", app.DeleteProfilePicture)
			router.Put("/direct-chat", app.PutDirectChat)
			router.Post("/group-chat", app.PostGroupChat)
			router.Post("/post", app.PostPost)
		})
	})
}

func (app *application) ParseAndValidateRequestBody(request *http.Request, into any) error {
	if err := json.NewDecoder(request.Body).Decode(into); err != nil {
		return err
	}
	if err := app.Validate.Struct(into); err != nil {
		return err
	}
	return nil
}

func (app *application) BeginTransa(writer http.ResponseWriter, request *http.Request) (transa pgx.Tx, ok bool) {
	transa, err := app.Database.Begin(request.Context())
	if err != nil {
		respondInternalServerError(writer, err, "failed to begin a transa")
		return nil, false
	}
	return transa, true
}

func (app *application) CommitTransa(writer http.ResponseWriter, request *http.Request, transa pgx.Tx) bool {
	if err := transa.Commit(request.Context()); err != nil {
		respondInternalServerError(writer, err, "failed to commit transa")
		return false
	}
	return true
}

/*
 * Validators
 */

func createValidate() *validator.Validate {
	validate := validator.New()
	validate.RegisterValidation("accountName", validateAccountName)
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("password", validatePassword)
	return validate
}

func validateAccountName(field validator.FieldLevel) bool {
	length := len(field.Field().String())
	return 3 <= length && length <= 100
}

func validateUsername(field validator.FieldLevel) bool {
	length := len(field.Field().String())
	return 3 <= length && length <= 100
}

func validatePassword(field validator.FieldLevel) bool {
	length := len(field.Field().String())
	return 8 <= length && length <= 100
}

/*
 * Environment Variables
 */

type environmentVariables struct {
	IsDevelopment bool
	DatabaseUrl   string
	ServerPort    string
	AccessSecret  string
}

func getEnvironmentVariables() environmentVariables {
	if err := godotenv.Load("../.env"); err != nil {
		log.Fatal(err);
	}

	environment := requireEnvironmentVariable("ENVIRONMENT")
	if environment != "production" && environment != "development" {
		log.Printf(".env.ENVIRONMENT is expected to be either production or development")
	}
	
	return environmentVariables{
		IsDevelopment: environment == "development",
		ServerPort:    requireEnvironmentVariable("SERVER_PORT"),
		DatabaseUrl:   requireEnvironmentVariable("DATABASE_URL"),
		AccessSecret:  requireEnvironmentVariable("ACCESS_SECRET"),
	}
}

func requireEnvironmentVariable(name string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		log.Fatal("Environment variable %s is not set: ", name)
	}
	return value
}

/*
 * Utilities
 */

type userClaimsKey struct {}

const accessTokenName = "access-token"

const (
	claimAccountId  = "sub"
	claimSessionId  = "sid"
	claimName       = "name"
	claimExpiresAt  = "exp"
)

func getUserId(contex context.Context) (string, bool) {
	claims, ok := contex.Value(userClaimsKey{}).(*jwt.MapClaims)
	if !ok {
		return "", false
	}
	
	accountId, ok := (*claims)[claimAccountId].(string)
	return accountId, ok
}

func getUserIdOrRespond(contex context.Context, writer http.ResponseWriter) (string, bool) {
	if accountId, ok := getUserId(contex); ok {
		return accountId, true
	}

	respondUnauthorized(writer)
	return "", false
}

func respondJson(writer http.ResponseWriter, status int, data any) error {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	return json.NewEncoder(writer).Encode(data)
}

func respondBadRequestError(writer http.ResponseWriter, err error) {
	respondBadRequestMessage(writer, err.Error())
}

func respondBadRequestMessage(writer http.ResponseWriter, message string) {
	http.Error(writer, "bad request: " + message, http.StatusBadRequest)
}

func respondNotFound(writer http.ResponseWriter) {
	http.Error(writer, "not found", http.StatusNotFound)
}

func respondNotFoundWhat(writer http.ResponseWriter, what string) {
	http.Error(writer, "not found: " + what, http.StatusNotFound)
}

func respondConflict(writer http.ResponseWriter, message string) {
	http.Error(writer, "conflict: " + message, http.StatusConflict)
}

func respondUnauthorized(writer http.ResponseWriter) {
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func respondPayloadTooLarge(writer http.ResponseWriter) {
	http.Error(writer, "payload too large", http.StatusRequestEntityTooLarge)
}

func respondTooManyRequests(writer http.ResponseWriter) {
	http.Error(writer, "too many requests", http.StatusTooManyRequests)
}

func respondInternalServerError(writer http.ResponseWriter, err error, description string, args ...any) {
	log.Println(append([]any{description}, append(args, err.Error())...)...)
	http.Error(writer, "internal server error", http.StatusInternalServerError)
}

func respondQueryFailed(writer http.ResponseWriter, err error, query string) {
	respondInternalServerError(writer, err, "query failed", query)
}

func nilIfEmptyString(value string) *string {
	if value != "" {
		return &value
	} else {
		return nil
	}
}

/*
 * Middlewares
 */

func (app *application) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(accessTokenName)
		if err != nil {
			respondUnauthorized(writer)
			return
		}

		token, err := jwt.ParseWithClaims(cookie.Value, &jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
			return []byte(app.Environment.AccessSecret), nil
		})
		if err != nil {
			respondUnauthorized(writer)
			return
		}

		claims, ok := token.Claims.(*jwt.MapClaims)
		if !ok || !token.Valid {
			respondUnauthorized(writer)
			return
		}

		const sqlCheckSession = `
			SELECT EXISTS (
				SELECT 1 FROM cu.session
				WHERE
					session.id = $1::UUID
					AND session.logout_at IS NULL
					AND session.expires_at > NOW()
			);
		`
		
		sessionId := (*claims)[claimSessionId].(string)
		var isValid bool
		if err := app.Database.
			QueryRow(request.Context(), sqlCheckSession, sessionId).
			Scan(&isValid); err != nil {

			respondQueryFailed(writer, err, sqlCheckSession)
			return
		}

		if (!isValid) {
			respondUnauthorized(writer)
			return
		}

		authenticatedContext := context.WithValue(request.Context(), userClaimsKey{}, claims)
		next.ServeHTTP(writer, request.WithContext(authenticatedContext))
	})
}

/*
 * Endpoints
 */

type LogupDto struct {
	Name     string `json:"name" validate:"required,accountName"`
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
}

// @Tags User
// @Summary Create account
// @Param body body LogupDto true "Account data"
// @Success 204
// @Router /logup [post]
func (app *application) PostLogup(writer http.ResponseWriter, request *http.Request) {
	var logup LogupDto
	if err := app.ParseAndValidateRequestBody(request, &logup); err != nil {
		respondBadRequestError(writer, err)
		return
	}

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return
	}
	defer transa.Rollback(request.Context())

	const sqlCheckUsernameAvailability = `
		SELECT EXISTS (
			SELECT 1 FROM cu.account
			WHERE
				account.username ILIKE $1::TEXT
				AND account.valid_to IS NULL
		);
	`
	var usernameIsTaken bool
	if err := transa.
		QueryRow(request.Context(), sqlCheckUsernameAvailability, logup.Username).
		Scan(&usernameIsTaken); err != nil {

		respondQueryFailed(writer, err, sqlCheckUsernameAvailability)
		return
	}
	if usernameIsTaken {
		respondConflict(writer, "The username is already used.")
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(logup.Password), bcrypt.DefaultCost)
	if err != nil {
		respondInternalServerError(writer, err, "failed to hash password")
		return
	}

	const sqlInsertAccount = `
		INSERT INTO cu.account (name, username, password)
		VALUES ($1::TEXT, LOWER($2::TEXT), $3::TEXT);
	`
	if _, err := transa.Exec(request.Context(), sqlInsertAccount, logup.Name, logup.Username, passwordHash); err != nil {
		respondQueryFailed(writer, err, sqlInsertAccount)
		return
	}

	if !app.CommitTransa(writer, request, transa) {
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type LoginDto struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
}

// @Tags User
// @Summary Authenticate
// @Description Generates the access-token cookie.
// @Param body body LoginDto true "Authentication payload"
// @Success 204
// @Router /login [post]
func (app *application) PostLogin(writer http.ResponseWriter, request *http.Request) {
	var login LoginDto
	if err := app.ParseAndValidateRequestBody(request, &login); err != nil {
		respondBadRequestError(writer, err)
		return
	}

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return;
	}
	defer transa.Rollback(request.Context())

	const sqlFindCredentials = `
		SELECT
			account.id,
			account.name,
			account.password
		FROM cu.account
		WHERE
			account.username ILIKE $1::TEXT
			AND account.valid_to IS NULL;
	`
	
	var (
		accountId uuid.UUID
		name      string
		password  string
	)
	
	if err := transa.
		QueryRow(request.Context(), sqlFindCredentials, login.Username).
		Scan(&accountId, &name, &password); err != nil {

		respondQueryFailed(writer, err, sqlFindCredentials)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(login.Password)); err != nil {
		http.Error(writer, "incorrect password", http.StatusUnauthorized)
		return
	}

	const sqlCreateSession = `
		INSERT INTO cu.session (account_id, expires_at)
		VALUES ($1::UUID, $2::TIMESTAMPTZ)
		RETURNING session.id::UUID;
	`
	var sessionId uuid.UUID
	expiresAt := time.Now().Add(time.Hour * 24)
	if err := transa.
		QueryRow(request.Context(), sqlCreateSession, accountId, expiresAt).
		Scan(&sessionId); err != nil {
		
		respondQueryFailed(writer, err, sqlCreateSession)
		return
	}

	if !app.CommitTransa(writer, request, transa) {
		return
	}

	claims := jwt.MapClaims{
		claimAccountId: accountId,
		claimSessionId: sessionId,
		claimName:      name,
		claimExpiresAt: expiresAt.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(app.Environment.AccessSecret))
	if err != nil {
		log.Println("failed to sign token", err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     accessTokenName,
		Value:    signedToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   !app.Environment.IsDevelopment,
	})
	writer.WriteHeader(http.StatusNoContent)
}

// @Tags User
// @Summary Commit unalive
// @Success 204
// @Router /logout [post]
func (app *application) PostLogout(writer http.ResponseWriter, request *http.Request) {
	claims := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	sessionId := (*claims)[claimSessionId].(string)

	const sqlLogout = `
		UPDATE cu.session
		SET logout_at = NOW()
		WHERE id = $1::UUID;
	`
	if _, err := app.Database.Exec(request.Context(), sqlLogout, sessionId); err != nil {
		respondQueryFailed(writer, err, sqlLogout)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     accessTokenName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !app.Environment.IsDevelopment,
	})
	writer.WriteHeader(http.StatusNoContent)
}

type ProfileResultDto struct {
	Id        string  `json:"id"`
	Name      string  `json:"name"`
	PictureId *string `json:"pictureId"`
}

// @Tags User
// @Summary See current user
// @Success 200 {object} ProfileResultDto "Current user profile"
// @Router /me [get]
func (app *application) GetMe(writer http.ResponseWriter, request *http.Request) {
	accountId, ok := getUserIdOrRespond(request.Context(), writer)
	if !ok {
		return
	}

	const sqlGetMe = `
		SELECT
			account.name,
			profile_picture.id
		FROM
			cu.account
			LEFT JOIN LATERAL (
				SELECT attach.id
				FROM cu.attach
				WHERE
					attach.kind = 'account_picture'
					AND attach.account_id = account.id
					AND attach.deleted_at IS NULL
				ORDER BY attach.created_at DESC
				LIMIT 1
			) AS profile_picture ON TRUE
		WHERE account.id = $1::UUID
	`

	var (
		name      string
		pictureId *string
	)
	
	if err := app.Database.
		QueryRow(request.Context(), sqlGetMe, accountId).
		Scan(&name, &pictureId); err != nil {

		respondQueryFailed(writer, err, sqlGetMe)
		return
	}
	
	resultDto := ProfileResultDto{
		Id: accountId,
		Name: name,
		PictureId: pictureId,
	}
	respondJson(writer, http.StatusOK, resultDto)
}

// @Tags User
// @Summary Update profile picture
// @Accept multipart/form-data
// @Param picture formData file true "Profile picture"
// @Success 204
// @Router /profile-picture [put]
func (app *application) PutProfilePicture(writer http.ResponseWriter, request *http.Request) {
	claims    := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	accountId := (*claims)[claimAccountId].(string)

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return;
	}
	defer transa.Rollback(request.Context())

	file, header, err := request.FormFile("picture")
	if err != nil {
		respondBadRequestMessage(writer, "invalid file")
		return
	}
	
	data, err := io.ReadAll(file)
	file.Close()
	if err != nil {
		respondBadRequestMessage(writer, "invalid file")
		return
	}

	const sqlDeleteAttach = `
		UPDATE cu.attach
		SET deleted_at = NOW()
		WHERE
			account_id = $1
			AND deleted_at IS NULL;
	`
	if _, err := transa.Exec(request.Context(), sqlDeleteAttach, accountId); err != nil {
		respondQueryFailed(writer, err, sqlDeleteAttach)
		return
	}

	const sqlInsertAttach = `
		INSERT INTO cu.attach (kind, account_id, filename, content)
		VALUES ('account_picture', $1::UUID, $2::TEXT, $3::BYTEA)
	`
	if _, err := transa.Exec(request.Context(), sqlInsertAttach, accountId, header.Filename, data); err != nil {
		respondQueryFailed(writer, err, sqlInsertAttach)
		return
	}

	if !app.CommitTransa(writer, request, transa) {
		return
	}
	
	writer.WriteHeader(http.StatusNoContent)
}

// @Tags User
// @Summary Remove profile picture
// @Success 204
// @Router /profile-picture [delete]
func (app *application) DeleteProfilePicture(writer http.ResponseWriter, request *http.Request) {
	claims    := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	accountId := (*claims)[claimAccountId].(string)

	const sqlDeleteAttach = `
		WITH soft_delete AS (
			UPDATE cu.attach
			SET deleted_at = NOW()
			WHERE
				account_id = $1
				AND kind = 'account_picture'
				AND deleted_at IS NULL
			RETURNING id
		)
		SELECT EXISTS (
			SELECT 1 FROM soft_delete
		);
	`
	var pictureExists bool
	if err := app.Database.
		QueryRow(request.Context(), sqlDeleteAttach, accountId).
		Scan(&pictureExists); err != nil {
		
		respondQueryFailed(writer, err, sqlDeleteAttach)
		return
	}
	
	if !pictureExists {
		respondNotFound(writer)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}
	
// @Tags Attachments
// @Summary Retrieve attachment file
// @Param id path string true "Attachment ID"
// @Success 200
// @Router /attach/{id} [get]
func (app *application) GetAttach(writer http.ResponseWriter, request *http.Request) {
	accountId, ok := getUserIdOrRespond(request.Context(), writer)
	if !ok {
		return
	}
	attachId  := chi.URLParam(request, "id")

	const sqlGetAttach = `
		WITH
		params AS (
			SELECT
				$1::UUID AS attach_id,
				$2::UUID AS account_id
		)
		SELECT
			attach.filename,
			attach.content
		FROM cu.attach
		INNER JOIN params ON params.attach_id = attach.id
		WHERE
			attach.deleted_at IS NULL
			AND
				CASE attach.kind
					WHEN 'account_picture' THEN TRUE
					WHEN 'chat_picture' THEN EXISTS (
						SELECT 1 FROM cu.member
						WHERE
							member.account_id = params.account_id
							AND member.chat_id = attach.chat_id
							AND member.valid_to IS NULL
					)
					WHEN 'post_file' THEN EXISTS (
						SELECT 1 FROM cu.member
						JOIN cu.post
							ON post.id = attach.post_id
							AND post.valid_to IS NULL
						JOIN cu.member AS poster
							ON poster.id = post.member_id
							AND poster.chat_id = member.chat_id
							AND poster.valid_to IS NULL
						WHERE
							member.account_id = params.account_id
							AND member.valid_to IS NULL
					)
				END;
	`
	
	var filename string
	var data     []byte
	if err := app.Database.
		QueryRow(request.Context(), sqlGetAttach, attachId, accountId).
		Scan(&filename, &data); err != nil {

		if err == pgx.ErrNoRows {
			respondNotFound(writer)
		} else {
			respondQueryFailed(writer, err, sqlGetAttach)
		}
		
		return
	}

	writer.Header().Set("Content-Disposition", `inline; filename="` + filename + `"`)
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusOK)
	writer.Write(data)
}

type UpdateDirectChatDto struct {
	OtherAccountId uuid.UUID `json:"otherAccountId" validate:"required"`
	DoPin          *bool     `json:"doPin,omitempty"`
	DoFriend       *bool     `json:"doFriend,omitempty"`
	DoMute         *bool     `json:"doMute,omitempty"`
	DoBlock        *bool     `json:"doBlock,omitempty"`
}

type CreateChatResultDto struct {
	ChatId uuid.UUID `json:"chatId"`
}

// @Tags Chat
// @Summary Update direct chat with another user.
// @Param body body UpdateDirectChatDto true "Direct chat options."
// @Success 204 "Changes applied to direct chat."
// @Success 201 {object} CreateChatResultDto "Direct chat created."
// @Router /direct-chat [put]
func (app *application) PutDirectChat(writer http.ResponseWriter, request *http.Request) {
	claims        := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	userAccountId := (*claims)[claimAccountId].(string)

	var chat UpdateDirectChatDto
	if err := app.ParseAndValidateRequestBody(request, &chat); err != nil {
		respondBadRequestError(writer, err)
		return
	}

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return;
	}
	defer transa.Rollback(request.Context())
	
	const sqlFindChat = `
		WITH params AS (
			SELECT
				$1::UUID AS user_account_id,
				$2::UUID AS his_account_id
		)
		SELECT
			chat.id                                        AS "chatId",
			user_member.is_chat_pinned                     AS "isUsersPin",
			COALESCE(user_member.is_direct_friend, FALSE)  AS "isUsersFriend",
			COALESCE(his_member.is_direct_friend, FALSE)   AS "isHisFriend",
			user_member.is_chat_muted                      AS "isUsersMute",
			COALESCE(user_member.is_direct_blocked, FALSE) AS "isUsersBlock",
			COALESCE(his_member.is_direct_blocked, FALSE)  AS "isHisBlock"
		FROM
			cu.chat
			INNER JOIN cu.member AS user_member
				ON user_member.chat_id = chat.id
				AND user_member.valid_to IS NULL
			INNER JOIN cu.member AS his_member
				ON his_member.chat_id = chat.id
				AND his_member.valid_to IS NULL
			INNER JOIN params
				ON params.user_account_id = user_member.account_id
				AND params.his_account_id = his_member.account_id
		WHERE
			chat.kind = 'direct'::cu.chat_kind
			AND chat.valid_to IS NULL
		LIMIT 1
	`
	var (
		chatId        uuid.UUID
		isUsersPin    bool
		isUsersFriend bool
		isHisFriend   bool
		isUsersMute   bool
		isUsersBlock  bool
		isHisBlock    bool
	)
	err := transa.
		QueryRow(request.Context(), sqlFindChat, userAccountId, chat.OtherAccountId).
		Scan(&chatId, &isUsersPin, &isUsersFriend, &isHisFriend, &isUsersMute, &isUsersBlock, &isHisBlock)
	if err == nil {
		if isHisBlock {
			respondConflict(writer, "you are blocked")
			return
		}

		if chat.DoFriend != nil && *chat.DoFriend == isUsersFriend { chat.DoFriend = nil }
		if chat.DoPin != nil && *chat.DoPin == isUsersPin          { chat.DoPin = nil }
		if chat.DoMute != nil && *chat.DoMute == isUsersMute       { chat.DoMute = nil }
		if chat.DoBlock != nil && *chat.DoBlock == isUsersBlock    { chat.DoBlock = nil }

		if chat.DoFriend == nil && chat.DoPin == nil && chat.DoMute == nil && chat.DoBlock == nil {
			respondConflict(writer, "nothing to update")
			return
		}

		if chat.DoFriend != nil && *chat.DoFriend && !isHisFriend {
			// TODO: Notify friend request.
		}

		const sqlUpdateChat = `
			WITH params AS (
				SELECT
					$1::UUID AS chat_id,
					$2::UUID AS user_account_id,
					$3::BOOLEAN AS is_user_pin,
					$4::BOOLEAN AS is_user_mute,
					$5::BOOLEAN AS is_user_friend,
					$6::BOOLEAN AS is_user_block
			)
			UPDATE cu.member AS member
			SET
				is_chat_pinned    = COALESCE(params.is_user_pin, member.is_chat_pinned),
				is_chat_muted     = COALESCE(params.is_user_mute, member.is_chat_muted),
				is_direct_friend  = COALESCE(params.is_user_friend, member.is_direct_friend),
				is_direct_blocked = COALESCE(params.is_user_block, member.is_direct_blocked)
			FROM params
			WHERE
				member.account_id = params.user_account_id
				AND member.chat_id = params.chat_id
				AND member.valid_to IS NULL;
		`
		if _, err := transa.Exec(request.Context(), sqlUpdateChat, chatId, userAccountId, chat.DoPin, chat.DoMute, chat.DoFriend, chat.DoBlock); err != nil {
			respondQueryFailed(writer, err, sqlUpdateChat)
			return
		}
		
		writer.WriteHeader(http.StatusNoContent)
	} else if err == pgx.ErrNoRows {
		const sqlCreateChat = `
			WITH params AS (
				SELECT
					$1::UUID    AS user_account_id,
					$2::UUID    AS his_account_id,
					$3::BOOLEAN AS is_user_pin,
					$4::BOOLEAN AS is_user_mute,
					$5::BOOLEAN AS is_user_friend,
					$6::BOOLEAN AS is_user_block
			),
			chat AS MATERIALIZED (
				INSERT INTO cu.chat (kind, name)
				VALUES ('direct'::cu.chat_kind, '')
				RETURNING chat.id
			),
			members AS MATERIALIZED (
				INSERT INTO cu.member (
					account_id,
					chat_id,
					is_chat_pinned,
					is_chat_muted,
					is_direct_friend,
					is_direct_blocked
				) (
					SELECT
						params.user_account_id::UUID,
						chat.id,
						COALESCE(params.is_user_pin, FALSE),
						COALESCE(params.is_user_mute, FALSE),
						params.is_user_friend,
						params.is_user_block
					FROM
						chat,
						params
					UNION ALL
					SELECT
						params.his_account_id::UUID,
						chat.id,
						FALSE,
						FALSE,
						NULL,
						NULL
					FROM
						chat,
						params
				)
				RETURNING member.id
			)
			SELECT chat.id
			FROM
				chat,
				members;
		`
		
		var chatId uuid.UUID
		
		if err := transa.
			QueryRow(request.Context(), sqlCreateChat, userAccountId, chat.OtherAccountId, chat.DoPin, chat.DoFriend, chat.DoMute, chat.DoBlock).
			Scan(&chatId); err != nil {

			respondQueryFailed(writer, err, sqlCreateChat)
			return
		}

		result := CreateChatResultDto{ChatId: chatId}
		respondJson(writer, http.StatusCreated, result)
	} else {
		respondQueryFailed(writer, err, sqlFindChat)
		return
	}
	
	app.CommitTransa(writer, request, transa)
}

// @Tags Chat
// @Summary Create a group chat
// @Accept multipart/form-data
// @Param name formData string true "The name of the group"
// @Param description formData string false "The description of the group"
// @Param accountIds formData []string true "Account IDs of the members"
// @Param picture formData file false "Group picture"
// @Success 201 {object} CreateChatResultDto "The group is created."
// @Router /group-chat [post]
func (app *application) PostGroupChat(writer http.ResponseWriter, request *http.Request) {
	userAccountId, ok := getUserIdOrRespond(request.Context(), writer)
	if !ok {
		return
	}
	_ = userAccountId

	const formCapacity = 1024 * 1024 * 32 // 32 MB
	const maxFileSize  = 1024 * 1024 * 10 // 10 MB
	
	if err := request.ParseMultipartForm(formCapacity); err != nil {
		respondBadRequestError(writer, err)
		return
	}

	name             := request.FormValue("name")
	description      := nilIfEmptyString(request.FormValue("description"))
	memberAccountIds := request.MultipartForm.Value["accountIds"]
	picture, pictureHeader, err := request.FormFile("picture")
	
	if err != nil {
		respondBadRequestError(writer, err)
		return
	}

	var (
		pictureData     []byte
		pictureFilename *string
	)
	
	if picture != nil && pictureHeader != nil {
		defer picture.Close()
		
		if pictureHeader.Size >= maxFileSize {
			respondPayloadTooLarge(writer)
			return
		}

		pictureData, err = io.ReadAll(picture)
		if err != nil {
			respondBadRequestMessage(writer, "invalid file")
			return
		}

		pictureFilename = &pictureHeader.Filename
	}

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return
	}
	defer transa.Rollback(request.Context())
	
	const sqlCheckAccountsExist = `
		SELECT COUNT(*) = CARDINALITY($1::UUID[])
		FROM cu.account
		WHERE
			account.id = ANY($1::UUID[])
			AND account.id <> $2::UUID
			AND account.valid_to IS NULL
	`

	var membersExist bool
	
	if err := transa.
		QueryRow(request.Context(), sqlCheckAccountsExist, memberAccountIds, userAccountId).
		Scan(&membersExist); err != nil {

		respondQueryFailed(writer, err, sqlCheckAccountsExist)
		return
	}

	if !membersExist {
		respondNotFound(writer)
		return
	}

	const sqlCreateChat = `
		WITH params AS (
			SELECT
				$1::UUID   AS user_account_id,
				$2::UUID[] AS member_account_ids,
				$3::TEXT   AS group_name,
				$4::TEXT   AS group_description,
				$5::TEXT   AS picture_filename,
				$6::BYTEA  AS picture
		),
		chat AS MATERIALIZED (
			INSERT INTO cu.chat (kind, name, description)
			SELECT
				'group'::cu.chat_kind,
				params.group_name,
				params.group_description
			FROM params
			RETURNING chat.id
		),
		attach AS MATERIALIZED (
			INSERT INTO cu.attach (kind, chat_id, filename, content)
			SELECT
				'chat_picture',
				chat.id,
				params.picture_filename,
				params.picture
			FROM
				chat,
				params
			WHERE params.picture IS NOT NULL
		),
		members AS MATERIALIZED (
			INSERT INTO cu.member (
				account_id,
				chat_id,
				is_group_admin,
				is_group_owner
			) (
				SELECT
					params.user_account_id,
					chat.id,
					TRUE,
					TRUE
				FROM
					chat,
					params
				UNION ALL
				SELECT
					account_id,
					chat.id,
					FALSE,
					FALSE
				FROM
					params,
					UNNEST(params.member_account_ids) AS account_id,
					chat
			)
			RETURNING member.id
		)
		SELECT chat.id
		FROM chat;
	`

	var chatId uuid.UUID
	
	if err := transa.
		QueryRow(request.Context(), sqlCreateChat, userAccountId, memberAccountIds, name, description, pictureFilename, pictureData).
		Scan(&chatId); err != nil {

		respondQueryFailed(writer, err, sqlCreateChat)
		return
	}

	if !app.CommitTransa(writer, request, transa) {
		return
	}
	
	respondJson(writer, http.StatusCreated, CreateChatResultDto{ChatId: chatId})
}

type CreatePostResultDto struct {
	PostId uuid.UUID `json:"postId"`
}

// @Tags Post
// @Summary Send a post in the chat.
// @Accept multipart/form-data
// @Param chatId formData string true "Chat Id"
// @Param replyToId formData string false "Reply to Post ID"
// @Param message formData string false "Message"
// @Param attach formData []file false "Attachments (multiple files)"
// @Success 201 {object} CreatePostResultDto "The post is posted."
// @Router /post [post]
func (app *application) PostPost(writer http.ResponseWriter, request *http.Request) {
	claims        := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	userAccountId := (*claims)[claimAccountId].(string)

	const formCapacity = 1024 * 1024 * 32 // 32 MB
	const maxFileSize  = 1024 * 1024 * 10 // 10 MB
	
	if err := request.ParseMultipartForm(formCapacity); err != nil {
		respondBadRequestError(writer, err)
		return
	}

	chatId    := request.FormValue("chatId")
	replyToId := nilIfEmptyString(request.FormValue("replyToId"))
	message   := nilIfEmptyString(request.FormValue("message"))
	files     := request.MultipartForm.File["attach"]

	if message == nil && len(files) == 0 {
		respondBadRequestMessage(writer, "please send a message or some files")
		return
	}
	
	filenames := make([]string, 0, len(files))
	contents  := make([][]byte, 0, len(files))
	for _, header := range files {
		if header.Size > maxFileSize {
			respondPayloadTooLarge(writer)
			return
		}
		
		file, err := header.Open()
		if err != nil {
			respondInternalServerError(writer, err, "failed to open file")
			return
		}

		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			respondInternalServerError(writer, err, "failed to read file")
			return
		}

		filenames = append(filenames, header.Filename)
		contents = append(contents, data)
	}

	transa, ok := app.BeginTransa(writer, request)
	if !ok {
		return
	}
	defer transa.Rollback(request.Context())
	
	const sqlCheckChatState = `
		WITH
		params AS (
			SELECT
				$1::UUID AS chat_id,
				$2::UUID AS account_id,
				$3::UUID AS replied_to_id
		)
		SELECT
			COALESCE(other_member.is_direct_blocked, FALSE),
			COALESCE(last_post.valid_from, NOW() - INTERVAL'100 years'),
			replied_post.id IS NOT NULL
		FROM
			cu.chat
			CROSS JOIN params
			INNER JOIN cu.member
				ON member.account_id = params.account_id
				AND member.chat_id = chat.id
				AND member.valid_to IS NULL
			LEFT JOIN cu.member AS other_member
				ON chat.kind = 'direct'::cu.chat_Kind
				AND other_member.chat_id = chat.id
				AND other_member.valid_to IS NULL
			LEFT JOIN LATERAL (
				SELECT post.valid_from
				FROM cu.post
				WHERE post.member_id = member.id
				ORDER BY post.valid_from DESC
				LIMIT 1
			) AS last_post ON TRUE
			LEFT JOIN cu.post AS replied_post
				ON replied_post.id = params.replied_to_id
				AND replied_post.valid_to IS NULL
				AND EXISTS (
					SELECT 1 FROM cu.member
					WHERE
						member.id = replied_post.member_id
						AND member.chat_id = chat.id
						AND member.valid_to IS NULL
					)
		WHERE
			chat.id = params.chat_id
			AND chat.valid_to IS NULL;
	`

	var (
		isBlocked         bool
		lastPostTime      time.Time
		repliedPostExists bool
	)

	err := transa.
		QueryRow(request.Context(), sqlCheckChatState, chatId, userAccountId, replyToId).
		Scan(&isBlocked, &lastPostTime, &repliedPostExists)
	if err == pgx.ErrNoRows {
		respondNotFoundWhat(writer, "chat")
		return
	} else if err != nil {
		respondQueryFailed(writer, err, sqlCheckChatState)
		return
	}

	if isBlocked {
		respondConflict(writer, "you've been blocked")
		return
	}
	
	if time.Since(lastPostTime) < 200 * time.Millisecond {
		respondTooManyRequests(writer)
		return
	}

	if replyToId != nil && !repliedPostExists {
		respondNotFoundWhat(writer, "post")
		return
	}

	const sqlPostPost = `
		WITH
		params AS (
			SELECT
				$1::UUID    AS account_id,
				$2::TEXT    AS message,
				$3::UUID    AS reply_to_id,
				$4::TEXT[]  AS filenames,
				$5::BYTEA[] AS contents
		),
		post AS MATERIALIZED (
			INSERT INTO cu.post (member_id, reply_to_id, message)
			SELECT
				member.id,
				params.reply_to_id,
				params.message
			FROM params
			INNER JOIN cu.member
				ON member.account_id = params.account_id
				AND member.valid_to IS NULL
			RETURNING post.id
		),
		attach AS MATERIALIZED (
			INSERT INTO cu.attach (kind, post_id, filename, content)
			SELECT
				'post_file'::cu.attach_kind,
				post.id,
				filename.value,
				content.value
			FROM
				params
				CROSS JOIN post
				CROSS JOIN UNNEST(params.filenames) WITH ORDINALITY AS filename (value, ord)
				INNER JOIN UNNEST(params.contents)  WITH ORDINALITY AS content  (value, ord) USING (ord)
			RETURNING attach.id
		)
		SELECT post.id
		FROM post;
	`

	var postId uuid.UUID

	if err = transa.
		QueryRow(request.Context(), sqlPostPost, userAccountId, message, replyToId, filenames, contents).
		Scan(&postId); err != nil {

		respondQueryFailed(writer, err, sqlPostPost)
		return
	}

	if !app.CommitTransa(writer, request, transa) {
		return
	}

	respondJson(writer, http.StatusCreated, CreatePostResultDto{PostId: postId})
}
