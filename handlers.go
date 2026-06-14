package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Invalid method %s for /register", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Пошаговый план:
	// 1. Распарсите JSON из тела запроса в структуру RegisterRequest
	// 2. Проведите валидацию данных (email, username, password)
	// 3. Проверьте, что пользователь с таким email не существует
	// 4. Захешируйте пароль с помощью функции HashPassword()
	// 5. Создайте пользователя в БД с помощью CreateUser()
	// 6. Сгенерируйте JWT токен с помощью GenerateToken()
	// 7. Верните ответ с токеном и данными пользователя
	//
	// Подсказки:
	// - Используйте json.NewDecoder(r.Body).Decode() для парсинга JSON
	// - Проверьте что все обязательные поля заполнены
	// - При ошибках возвращайте соответствующие HTTP статусы
	// - 400 для невалидных данных, 409 для дубликатов, 500 для внутренних ошибок
	// - Не забудьте установить Content-Type: application/json для ответа

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest

	// Парсинг JSON из тела запроса
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Валидация данных
	if req.Email == "" || req.Username == "" || req.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Проверка существования пользователя с таким email
	existingUserPtr, err := GetUserByEmail(req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			log.Printf("No existing user with email %s, proceeding with registration", req.Email)
			existingUserPtr = nil // Пользователь не найден, продолжать регистрацию с новым email
		} else { // Обработка других ошибок БД
			log.Printf("Error checking existing user by email: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	if existingUserPtr != nil {
		log.Printf("User with E-mail %s already exists,checking credentials", existingUserPtr.Email)
	} else {
		hashedPassword, err := HashPassword(req.Password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Создать пользователя в БД
		newUserPtr, err := CreateUser(req.Email, req.Username, hashedPassword)
		if err != nil {
			log.Printf("Error creating user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("New user created with email %s and username %s and hashed password %s", newUserPtr.Email, newUserPtr.Username, hashedPassword)
		existingUserPtr = newUserPtr
	}
	// Сгенерировать JWT токен
	tokenStr, err := GenerateToken(existingUserPtr)
	if err != nil {
		log.Printf("Error generating token: %v, email %s", err, existingUserPtr.Email)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201 Created

	response := AuthResponse{
		Token: tokenStr,
		User:  *existingUserPtr,
	}
	json.NewEncoder(w).Encode(response)
	//http.Error(w, "Registration not implemented", http.StatusNotImplemented)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Пошаговый план:
	// 1. Распарсите JSON из тела запроса в структуру LoginRequest
	// 2. Проведите базовую валидацию (email и password не пустые)
	// 3. Найдите пользователя по email с помощью GetUserByEmail()
	// 4. Проверьте пароль с помощью CheckPassword()
	// 5. Сгенерируйте JWT токен с помощью GenerateToken()
	// 6. Верните ответ с токеном и данными пользователя
	//
	// Важные моменты безопасности:
	// - При неверном email или пароле возвращайте одинаковое сообщение
	//   "Invalid email or password" чтобы не раскрывать существование email
	// - Используйте HTTP статус 401 для неверных учетных данных
	// - Не возвращайте password_hash в ответе
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Распарсите JSON из тела запроса в структуру LoginRequest
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 2. Проведите базовую валидацию (email и password не пустые)
	if loginReq.Email == "" || loginReq.Password == "" {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 3. Найдите пользователя по email с помощью GetUserByEmail()
	user, err := GetUserByEmail(loginReq.Email)
	if err != nil {
		// Не раскрываем информацию о том, существует ли пользователь
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 4. Проверьте пароль с помощью CheckPassword()
	if !CheckPassword(user.PasswordHash, loginReq.Password) {
		// Не раскрываем информацию о том, существует ли пользователь
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 5. Сгенерируйте JWT токен с помощью GenerateToken()
	token, err := GenerateToken(user)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 6. Верните ответ с токеном и данными пользователя (без пароля)
	response := map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			// Добавьте другие необходимые поля, но не password_hash
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	//http.Error(w, "Login not implemented", http.StatusNotImplemented)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Реализуйте получение профиля пользователя
	//
	// Пошаговый план:
	// 1. Получите ID пользователя из контекста с помощью GetUserIDFromContext()
	// 2. Загрузите данные пользователя из БД с помощью GetUserByID()
	// 3. Верните данные пользователя в JSON формате
	//
	// Примечания:
	// - Этот обработчик вызывается только после AuthMiddleware
	// - Контекст уже должен содержать userID
	// - Если пользователь не найден - верните 404
	// - Не включайте password_hash в ответ

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получите ID пользователя из контекста
	userID, ok := GetUserIDFromContext(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Загрузите данные пользователя из БД
	user, err := GetUserByID(userID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Удалите password_hash из ответа
	user.PasswordHash = ""
	// Верните данные пользователя в JSON формате
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}

	//	http.Error(w, "Profile not implemented", http.StatusNotImplemented)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	// TODO: Добавьте дополнительные проверки
	// - Используйте ValidateEmail() и ValidatePassword() из auth.go
	// Проверка формата email
	if err := ValidateEmail(req.Email); err != nil {
		return fmt.Errorf("email validation failed: %w", err)
	}

	// TODO: Добавьте дополнительные проверки, например, для пароля
	if err := ValidatePassword(req.Password); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// - Проверьте длину username (например, минимум 3 символа)
	if len(req.Username) < 8 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	// - Проверьте что username содержит только допустимые символы
	//const usernameRegex = `^[a-zA-Z0-9._-]+$`	//  только буквы, цифры, точки, дефисы и подчеркивания
	const usernameRegex = `^[a-zA-Z0-9._]+$` //  только буквы, цифры, точки и подчеркивания
	matched, err := regexp.MatchString(usernameRegex, req.Username)
	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("username %s contains invalid characters;", req.Username)
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
