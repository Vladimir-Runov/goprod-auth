package main

import (
	"context"
	"net/http"
	"strings"
)

// AuthMiddleware проверяет JWT токен и устанавливает контекст пользователя
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Импортируйте "context" и "strings"
		// 2. Получите заголовок Authorization из запроса
		// 3. Проверьте, что заголовок не пустой
		// 4. Проверьте формат "Bearer <token>" и извлеките токен
		// 5. Валидируйте токен с помощью ValidateToken() из auth.go
		// 6. Добавьте данные пользователя в контекст запроса
		// 7. Передайте управление следующему обработчику
		// Если токен невалиден - верните 401 Unauthorized
		// Если токен отсутствует - верните 401 Unauthorized

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}

		ctx := context.WithValue(r.Context(), "ID", claims.ID) //	Добавляем данные пользователя в контекст запроса
		r = r.WithContext(ctx)                                 // Обновляем запрос с новым контекстом
		next.ServeHTTP(w, r)                                   // Передайте управление следующему обработчику
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value("ID").(int)
	return userID, ok

}
