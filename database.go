package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// Глобальная переменная для подключения к БД
var db *sql.DB
var ErrUserNotFound = errors.New("user not found")

// InitDB инициализирует подключение к базе данных
// 1. Составьте строку подключения используя fmt.Sprintf()
//    Формат: "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable"
// 2. Получите параметры из переменных окружения с помощью getEnv()
// 3. Откройте соединение с sql.Open("postgres", connStr)
// 4. Проверьте подключение с помощью db.Ping()
// 5. Обработайте ошибки на каждом шаге
//
// Переменные окружения: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

func InitSecureDB() error {
	log.Printf("database.InitSecureDB()")
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", "postgres"),
		getEnv("DB_NAME", "secure_service"),
	)
	log.Print(getEnv("DB_HOST", "localhost"))

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// CreateUser создает нового пользователя в базе данных postgres
// TODO: Реализуйте создание пользователя
// КРИТИЧЕСКИ ВАЖНО: Используйте параметризованный запрос для защиты от SQL-инъекций!
//
// Что нужно сделать:
// 1. Создайте SQL запрос с плейсхолдерами $1, $2, $3
//    INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at
// 2. Выполните запрос с db.QueryRow(query, email, username, passwordHash)
// 3. Считайте результат в переменные user.ID и user.CreatedAt
// 4. Заполните остальные поля структуры User
// 5. Обработайте ошибки
//
// НИКОГДА не используйте fmt.Sprintf для построения SQL запросов!
// SQL запрос с плейсхолдерами

func CreateUser(email, username, passwordHash string) (*User, error) {
	log.Printf("database.CreateUser(%v,%v,%v)", email, username, passwordHash)
	query := `
	INSERT INTO users (email, username, password_hash)
	VALUES ($1, $2, $3)
	RETURNING id, created_at
	`

	var user User

	// Выполнение запроса
	err := db.QueryRow(query, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not created: no rows affected")
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	user.Email = email
	user.Username = username
	user.PasswordHash = passwordHash // возвращаем password_hash для отладки, но не используйте его
	// возвращает указатель на локальную переменную типа User.
	// В Go эта переменная будет размещена в куче (heap), а не на стеке (stack), что позволяет ей сохраняться после выхода из функции.
	return &user, nil
}

// GetUserByEmail находит пользователя по email
func GetUserByEmail(email string) (*User, error) {
	log.Printf("database.GetUserByEmail(%v)", email)
	query := `SELECT id, email, username, password_hash, created_at FROM users WHERE email = $1`
	var user User
	err := db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt) // Считайте все поля в структуру User с помощью Scan()

	if err != nil {
		log.Printf("\t\terror %s %v", email, err)
		if err == sql.ErrNoRows { // Если пользователь не найден, возвращаем nil и ошибку
			log.Printf("\t\t ...(no rows in result set) %s", email)
			return nil, ErrUserNotFound //  nil для пользователя и ErrUserNotFound (no rows in result set) для ошибки, чтобы указать на отсутствие пользователя
		}
		// Обработка других ошибок БД
		log.Printf("\t\temail= %s", email)
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	log.Printf("\t\treturn User %v", user)
	// возвращает указатель на локальную переменную типа User.
	// В Go эта переменная будет размещена в куче (heap), а не на стеке (stack), что позволяет ей сохраняться после выхода из функции.
	return &user, nil
}

// GetUserByID находит пользователя по ID
func GetUserByID(userID int) (*User, error) {
	log.Printf("database.GetUserByID(%v)", userID)
	query := `SELECT id, email, username, created_at FROM users WHERE id = $1`

	var user User
	err := db.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Username, &user.CreatedAt) // Считайте все поля в структуру User с помощью Scan()
	if err != nil {
		if err == sql.ErrNoRows { // Если пользователь не найден, возвращаем nil и ошибку
			return nil, ErrUserNotFound //  nil для пользователя и ErrUserNotFound  для ошибки, чтобы указать на отсутствие пользователя
		}
		// Обработка других ошибок БД
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
	//	return nil, fmt.Errorf("not implemented - реализуйте поиск пользователя по ID")
}

// GetAllUsers возвращает всех пользователей из таблицы users
func GetAllUsers() ([]User, error) {
	log.Printf("database.GetAllUsers()")
	query := "SELECT id, email, username, password_hash, created_at FROM users"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("failed to get users: %v", err)
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer rows.Close() // Закрываем rows после завершения работы с ними

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt)
		if err != nil {
			log.Printf("failed to scan user: %v", err)
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user) // Добавляем пользователя в массив
	}

	if err := rows.Err(); err != nil {
		log.Printf("error occurred during iteration: %v", err)
		return nil, fmt.Errorf("error occurred during iteration: %w", err)
	}

	return users, nil // Возвращаем массив пользователей
}

// UserExistsByEmail проверяет, существует ли пользователь с данным email
func UserExistsByEmail(email string) (bool, error) {
	log.Printf("database.UserExistsByEmail(%v)", email)
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	var exists bool = false
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		log.Printf("database.UserExistsByEmail error: %v", err)
		return false, fmt.Errorf("failed to check user exists by email: %w", err)
	}
	log.Printf("database.UserExistsByEmail exists!: %v", exists)
	return exists, nil
	//return false, fmt.Errorf("not implemented - реализуйте проверку существования пользователя")
}

// GetDB возвращает подключение к базе данных (для тестирования)
func GetDB() *sql.DB {
	log.Printf("database.GetDB()")
	return db
}
