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

	validate := validator.New()
	validate.RegisterValidation("accountName", validateAccountName)
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("password", validatePassword)
	
	router := chi.NewRouter()

	app := application{
		Environment: environment,
		Database:    connectionPool,
		Validate:    validate,
	}
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
			router.Put("/profile-picture", app.PutProfilePicture)
			router.Delete("/profile-picture", app.DeleteProfilePicture)
			router.Get("/profile-picture", app.GetProfilePicture)
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

func respondConflict(writer http.ResponseWriter, message string) {
	http.Error(writer, "conflict: " + message, http.StatusConflict)
}

func respondUnauthorized(writer http.ResponseWriter) {
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func respondInternalServerError(writer http.ResponseWriter, err error, description string, args ...any) {
	log.Println(append([]any{description}, append(args, err.Error())...)...)
	http.Error(writer, "internal server error", http.StatusInternalServerError)
}

func respondQueryFailed(writer http.ResponseWriter, err error, query string) {
	respondInternalServerError(writer, err, "query failed", query)
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
				SELECT 1
				FROM cu.session
				WHERE
					session.id = $1::UUID
					AND session.logout_at IS NULL
					AND session.expires_at > NOW()
			);
		`
		
		sessionId := (*claims)["sid"].(string)
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

	transaction, err := app.Database.Begin(request.Context())
	if err != nil {
		respondInternalServerError(writer, err, "failed to begin a transaction")
		return;
	}
	defer transaction.Rollback(request.Context())

	const sqlCheckUsernameAvailability = `
		SELECT EXISTS (
			SELECT 1
			FROM cu.account
			WHERE
				account.username ILIKE $1::TEXT
				AND account.valid_to IS NULL
		);
	`
	var usernameIsTaken bool
	if err := transaction.
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
	if _, err := transaction.Exec(request.Context(), sqlInsertAccount, logup.Name, logup.Username, passwordHash); err != nil {
		respondQueryFailed(writer, err, sqlInsertAccount)
		return
	}

	transaction.Commit(request.Context())
	writer.WriteHeader(http.StatusNoContent)
}

type LoginDto struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
}

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

	transaction, err := app.Database.Begin(request.Context())
	if err != nil {
		respondInternalServerError(writer, err, "failed to begin a transaction")
		return;
	}
	defer transaction.Rollback(request.Context())

	const sqlFindCredentials = `
		SELECT
			id,
			name,
			password
		FROM cu.account
		WHERE
			account.username ILIKE $1::TEXT
			AND account.valid_to IS NULL;
	`
	var accountId uuid.UUID
	var name      string
	var password  string
	if err := transaction.
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
	if err := transaction.
		QueryRow(request.Context(), sqlCreateSession, accountId, expiresAt).
		Scan(&sessionId); err != nil {
		
		respondQueryFailed(writer, err, sqlCreateSession)
		return
	}
	if err := transaction.Commit(request.Context()); err != nil {
		respondInternalServerError(writer, err, "failed to commit transaction")
		return
	}

	claims := jwt.MapClaims{
		"sub":  accountId,
		"sid":  sessionId,
		"name": name,
		"exp":  expiresAt.Unix(),
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

// @Summary Commit unalive
// @Success 204
// @Router /logout [post]
func (app *application) PostLogout(writer http.ResponseWriter, request *http.Request) {
	claims := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	sessionId := (*claims)["sid"].(string)

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
	Id   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// @Summary See current user
// @Success 200 {object} ProfileResultDto "Current user profile"
// @Router /me [get]
func (app *application) GetMe(writer http.ResponseWriter, request *http.Request) {
	claims := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)

	id, err := uuid.Parse((*claims)["sub"].(string))
	if err != nil {
		respondUnauthorized(writer)
		return
	}
	
	resultDto := ProfileResultDto{Id: id, Name: (*claims)["name"].(string)}
	respondJson(writer, http.StatusOK, resultDto)
}

// @Summary Update profile picture
// @Accept multipart/form-data
// @Param picture formData file true "Profile picture"
// @Success 204
// @Router /profile-picture [put]
func (app *application) PutProfilePicture(writer http.ResponseWriter, request *http.Request) {
	claims    := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	accountId := (*claims)["sub"].(string)

	transaction, err := app.Database.Begin(request.Context())
	if err != nil {
		respondInternalServerError(writer, err, "failed to begin a transaction")
		return;
	}
	defer transaction.Rollback(request.Context())

	file, header, err := request.FormFile("picture")
	if err != nil {
		respondBadRequestMessage(writer, "invalid file")
		return
	}
	
	data, err := io.ReadAll(file)
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
	if _, err := transaction.Exec(request.Context(), sqlDeleteAttach, accountId); err != nil {
		respondQueryFailed(writer, err, sqlDeleteAttach)
		return
	}

	const sqlInsertAttach = `
		INSERT INTO cu.attach (kind, account_id, filename, content)
		VALUES ('account_picture', $1::UUID, $2::TEXT, $3::BYTEA)
	`
	if _, err := transaction.Exec(request.Context(), sqlInsertAttach, accountId, header.Filename, data); err != nil {
		respondQueryFailed(writer, err, sqlInsertAttach)
		return
	}

	if err := transaction.Commit(request.Context()); err != nil {
		respondInternalServerError(writer, err, "failed to commit transaction")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// @Summary Remove profile picture
// @Success 204
// @Router /profile-picture [delete]
func (app *application) DeleteProfilePicture(writer http.ResponseWriter, request *http.Request) {
	claims    := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	accountId := (*claims)["sub"].(string)

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
			SELECT 1
			FROM soft_delete
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
	
// @Summary Retrieve profile picture
// @Success 200
// @Router /profile-picture [get]
func (app *application) GetProfilePicture(writer http.ResponseWriter, request *http.Request) {
	claims    := request.Context().Value(userClaimsKey{}).(*jwt.MapClaims)
	accountId := (*claims)["sub"].(string)

	const sqlFindProfilePicture = `
		SELECT
			attach.filename,
			attach.content
		FROM cu.attach
		WHERE
			attach.account_id = $1::UUID
			AND attach.kind = 'account_picture'
			AND attach.deleted_at IS NULL
	`
	
	var filename string
	var data     []byte
	if err := app.Database.
		QueryRow(request.Context(), sqlFindProfilePicture, accountId).
		Scan(&filename, &data); err != nil {

		if err == pgx.ErrNoRows {
			respondNotFound(writer)
		} else {
			respondQueryFailed(writer, err, sqlFindProfilePicture)
		}
		return
	}

	writer.Header().Set("Content-Disposition", `inline; filename="` + filename + `"`)
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusOK)
	writer.Write(data)
}
