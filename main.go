package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// Загрузка переменных окружения из .env файла
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// Инициализация JWT секретного ключа
	InitAuth()

	// TODO: Инициализация подключения к базе данных
	// Используйте функцию InitDB() из database.go
	if err := InitSecureDB(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer CloseDB()

	// TODO: Настройка HTTP маршрутов
	// Используйте обработчики из handlers.go
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/profile", AuthMiddleware(ProfileHandler))
	http.HandleFunc("/health", HealthHandler)

	//todo:  will be removed in pruduction!  debug ver. only
	http.HandleFunc("/lst", UsersListHandler)
	http.HandleFunc("/exit", ExitHandler)
	// <<<

	// Запуск сервера
	port := getEnv("SERVER_PORT", "8080")
	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("📝 Register: POST http://localhost:%s/register", port)
	log.Printf("🔐 Login: POST http://localhost:%s/login", port)
	log.Printf("👤 Profile: GET http://localhost:%s/profile (requires token)", port)
	log.Printf("❤️  Health: GET http://localhost:%s/health", port)

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// getEnv получает значение переменной окружения или возвращает значение по умолчанию
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
