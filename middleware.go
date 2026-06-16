package main

import (
	"context"
	"log"
	"net/http"
	"strings"
)

// AuthMiddleware проверяет JWT токен и устанавливает контекст пользователя
// 1. Импортируйте "context" и "strings"
// 2. Получите заголовок Authorization из запроса
// 3. Проверьте, что заголовок не пустой
// 4. Проверьте формат "Bearer <token>" и извлеките токен
// 5. Валидируйте токен с помощью ValidateToken() из auth.go
// 6. Добавьте данные пользователя в контекст запроса
// 7. Передайте управление следующему обработчику
// Если токен невалиден - верните 401 Unauthorized
// Если токен отсутствует - верните 401 Unauthorized

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	log.Printf("middleware.AuthMiddleware(%v)", next)
	return func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("\t\t authHeader = ''")
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("\t\t authHeader no prefix Bearer %v ", authHeader)
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		log.Printf("\t\t calling ValidateToken  %v ", tokenString)
		claims, err := ValidateToken(tokenString)
		if err != nil {
			log.Printf("\t\t token not valid! ")
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}
		log.Printf("\t\t oK! claims: %v ", claims)
		ctx := context.WithValue(r.Context(), "ID", claims.ID) //	Добавляем данные пользователя в контекст запроса
		r = r.WithContext(ctx)                                 // Обновляем запрос с новым контекстом
		next.ServeHTTP(w, r)                                   // Передайте управление следующему обработчику
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromRequestContext(r *http.Request) (int, bool) {
	log.Printf("GetUserIDFromContextEx : r.Context(%v) ", r.Context().Value)
	userID, ok := r.Context().Value("ID").(int)
	log.Printf("GetUserIDFromContextEx : userID(%v) ", userID)
	return userID, ok

}
