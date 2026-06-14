package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// var jwtSecret []byte - секретный ключ для подписи токена
var jwtSecret = []byte("your_secret_key")

func generateSecretKey(length int) (string, error) {

	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

// InitAuth инициализирует секретный ключ для JWT
func InitAuth() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) < 32 {
		// Генерируем новый секретный ключ
		newKey, err := generateSecretKey(32)
		if err != nil {
			panic(err)
		}

		// Устанавливаем новый ключ в переменную среды
		if err := os.Setenv("JWT_SECRET", newKey); err != nil {
			panic(err)
		}
		jwtSecret = []byte(os.Getenv("JWT_SECRET"))
		if len(jwtSecret) < 32 {
			panic("JWT_SECRET must be at least 32 characters long")
		}
	}
}

// HashPassword хеширует пароль с использованием bcrypt
func HashPassword(password string) (string, error) {
	// TODO: Реализуйте хеширование пароля
	//
	// Что нужно сделать:
	// 1. Импортируйте "golang.org/x/crypto/bcrypt"
	// 2. Используйте bcrypt.GenerateFromPassword()
	// 3. Передайте []byte(password) и bcrypt.DefaultCost
	// 4. Обработайте ошибку и верните результат как string
	//
	// Документация: https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
	//return "", fmt.Errorf("not implemented - реализуйте хеширование пароля с bcrypt")
}

// CheckPassword проверяет пароль против хеша
func CheckPassword(password, hash string) bool {
	// TODO: Реализуйте проверку пароля
	//
	// Что нужно сделать:
	// 1. Используйте bcrypt.CompareHashAndPassword()
	// 2. Передайте []byte(hash) и []byte(password)
	// 3. Верните true если ошибки нет, false если есть
	//
	// Документация: https://pkg.go.dev/golang.org/x/crypto/bcrypt#CompareHashAndPassword

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil

}

// GenerateToken создает JWT токен для пользователя
func GenerateToken(userPtr *User) (string, error) {
	// TODO: Реализуйте генерацию JWT токена
	//
	// Что нужно сделать:
	// 1. Импортируйте "time" и "github.com/golang-jwt/jwt/v5"
	// 2. Создайте Claims структуру с данными пользователя
	//    - Заполните UserID, Email, Username
	//    - Установите ExpiresAt на 24 часа вперед: jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	//    - Установите IssuedAt на текущее время: jwt.NewNumericDate(time.Now())
	// 3. Создайте токен с помощью jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 4. Подпишите токен с помощью token.SignedString(jwtSecret)
	//
	// Документация: https://pkg.go.dev/github.com/golang-jwt/jwt/v5
	//return "", fmt.Errorf("not implemented - реализуйте генерацию JWT токена")

	claims := Claims{
		UserID:           userPtr.ID,
		Email:            userPtr.Email,
		Username:         userPtr.Username,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now())},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

// ValidateToken проверяет и парсит JWT токен
func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{} // 1. Создайте пустую структуру claims := &Claims{}
	// 2. Используйте jwt.ParseWithClaims() для парсинга токена
	// 3. В keyFunc проверьте, что алгоритм подписи HMAC (*jwt.SigningMethodHMAC)
	// 4. Верните jwtSecret как ключ для проверки подписи
	// 5. Проверьте, что токен валиден (token.Valid)
	// 6. Верните claims и ошибку

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 3. В keyFunc проверь, что алгоритм подписи HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 4. Верни jwtSecret как ключ для проверки подписи
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token has expired at %v", time.Unix(int64(exp), 0))
			}
		}
	}

	return claims, nil // 6. Верни claims и ошибку
	//return nil, fmt.Errorf("not implemented - реализуйте валидацию JWT токена")
}

// ValidatePassword проверяет требования к паролю
// Базовая проверка, возвращает ошибку если пароль не соответствует требованиям
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// TODO: Добавьте дополнительные проверки если необходимо

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hasDigit := false   // - проверка наличия цифр
	hasUpper := false   // - проверка наличия заглавных букв
	hasSpecial := false // - проверка наличие специальных символов

	for _, char := range password {
		switch {
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateEmail проверяет формат email (базовая проверка)
// Базовая проверка, возвращает ошибку если Email не соответствует требованиям
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// TODO: Добавьте более строгую валидацию email если необходимо
	// Можно использовать regexp.MatchString() для проверки формата

	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(emailRegex, email)
	if err != nil {
		return fmt.Errorf("error checking email format: %v", err)
	}
	if !matched {
		return fmt.Errorf("invalid email format")
	}

	return nil
}
