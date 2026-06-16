package main

import (
	"context"
	"log"
	"net/http"
	"strings"
)

// Также лучше использовать единый понятный ключ, например что-то вроде userID, а не “ID”, потому что “ID” слишком общее имя.
// Ещё лучше в реальном проекте использовать отдельный тип для ключа контекста, чтобы избежать случайных пересечений.
type contextKey string

const userIDKey contextKey = "userID"

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
		claims, err := ValidateToken(tokenString)
		log.Printf("\t\t calling ValidateToken  %v claims.UserID=%v", tokenString, claims.UserID)
		if err != nil {
			log.Printf("\t\t token not valid! ")
			http.Error(w, "Unauthorized", http.StatusUnauthorized) // 401 Unauthorized
			return
		}
		log.Printf("\t\t oK! claims: %v ", claims)

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID) //	Добавляем ИД-пользователя в контекст запроса
		//В Claims у вас есть поле UserID, куда при генерации токена действительно записывается ID пользователя. Но в middleware вы берёте claims.ID.
		// Это не ваш UserID, а поле ID из встроенной структуры jwt.RegisteredClaims, то есть JWT ID (jti). Вы его нигде не заполняете, поэтому оно пустое. Дальше вы кладёте это значение в контекст под ключом “ID”, а затем в GetUserIDFromRequestContext пытаетесь достать его как int. Так как в контексте лежит не int, а фактически пустая строка, приведение типа не проходит, ok становится false, а userID остаётся равным нулю. Именно поэтому в логе появляется userID(0), а затем ProfileHandler no userID.
		//Здесь нужно использовать именно пользовательский ID из claims, то есть поле UserID, и класть в контекст его.
		// Но главная причина вашей текущей ошибки конкретно такая: в middleware используется claims.ID вместо claims.UserID.

		r = r.WithContext(ctx) // Обновляем запрос с новым контекстом
		next.ServeHTTP(w, r)   // Передайте управление следующему обработчику
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromRequestContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value(userIDKey).(int)
	log.Printf("GetUserIDFromContextEx : userID(%v) ", userID)
	return userID, ok

}
