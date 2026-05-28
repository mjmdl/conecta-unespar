package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	swagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"

	_ "api/docs"
)

func main() {
	if err := godotenv.Load("../.env"); err != nil {
		log.Fatal(err);
	}

	serverPort  := requireEnv("SERVER_PORT")
	databaseUrl := requireEnv("DATABASE_URL")
	_            = requireEnv("ACCESS_SECRET")
	
	connectionPool, err := pgxpool.New(context.Background(), databaseUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer connectionPool.Close()

	validate := validator.New()
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("password", validatePassword)
	
	app := appProvider{
		Database: connectionPool,
		Validate: validate,
	}
	
	router := chi.NewRouter()
	router.Get("/swagger/*", swagger.WrapHandler)
	router.Post("/login", app.PostLogin)
	http.ListenAndServe(":" + serverPort, router)
}

func requireEnv(name string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		log.Fatal("Environment variable %s is not set.", name)
	}
	return value
}

func validateUsername(field validator.FieldLevel) bool {
	length := len(field.Field().String())
	return 3 <= length && length <= 100
}

func validatePassword(field validator.FieldLevel) bool {
	length := len(field.Field().String())
	return 8 <= length && length <= 100
}

type appProvider struct {
	Database *pgxpool.Pool
	Validate *validator.Validate
}

type LoginDto struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
}

type LoginSuccessDto struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// @Summary Authenticate
// @Param body body LoginDto true "Authentication payload"
// @Success 201 {object} LoginSuccessDto
// @Router /login [post]
func (app *appProvider) PostLogin(writer http.ResponseWriter, request *http.Request) {
	accessTokenSecret := requireEnv("ACCESS_SECRET")
	
	var login LoginDto
	if err := json.NewDecoder(request.Body).Decode(&login); err != nil {
		http.Error(writer, "invalid format: " + err.Error(), http.StatusBadRequest)
		return
	}
	if err := app.Validate.Struct(login); err != nil {
		http.Error(writer, "validation failed: " + err.Error(), http.StatusBadRequest)
		return
	}

	transaction, err := app.Database.Begin(request.Context())
	if err != nil {
		log.Println("failed to begin a transaction", err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
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
	if err := transaction.QueryRow(request.Context(), sqlFindCredentials, login.Username).Scan(&accountId, &name, &password); err != nil {
		log.Println("query failed", sqlFindCredentials, err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
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
	if err := transaction.QueryRow(request.Context(), sqlCreateSession, accountId, expiresAt).Scan(&sessionId); err != nil {
		log.Println("query failed", sqlCreateSession, err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := transaction.Commit(request.Context()); err != nil {
		log.Println("failed to commit transaction", sqlCreateSession, err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub":  accountId,
		"sid":  sessionId,
		"name": name,
		"exp":  expiresAt.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(accessTokenSecret))
	if err != nil {
		log.Println("failed to sign token", err.Error())
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		return
	}

	success := LoginSuccessDto{
		AccessToken: signedToken,
		ExpiresAt: expiresAt,
	}
	writer.WriteHeader(http.StatusCreated)
	json.NewEncoder(writer).Encode(success)
}
