# Практическое задание: Безопасный сервис аутентификации

## 🎯 Цель задания

Разработать безопасный REST API сервис с функциями регистрации и аутентификации пользователей на Go.

## 📋 Что нужно реализовать

### Обязательный функционал:
- ✅ **Регистрация пользователя** с хешированием пароля (bcrypt)
- ✅ **Вход в систему** с выдачей JWT токена
- ✅ **Защищенный эндпоинт** для получения профиля (требует JWT)
- ✅ **Защита от SQL-инъекций** (параметризованные запросы)

### API эндпоинты:
| Метод | Путь | Описание | Требует токен |
|-------|------|----------|--------------|
| POST | `/register` | Регистрация пользователя | Нет |
| POST | `/login` | Вход в систему | Нет |
| GET | `/profile` | Получить профиль | **Да** |
| GET | `/health` | Проверка состояния | Нет |

## 🏗️ Структура проекта

```
secure-service/
├── main.go              # Главный файл с запуском сервера
├── handlers.go          # HTTP обработчики
├── models.go            # Структуры данных
├── database.go          # Работа с БД
├── auth.go              # JWT и bcrypt
├── middleware.go        # Проверка токена
├── docker-compose.yml   # PostgreSQL в Docker
├── init.sql             # Схема БД
├── .env                 # Конфигурация (создать из .env.example)
├── go.mod               # Зависимости
└── README.md           # Этот файл
```

## 🚀 Быстрый старт

### 1. Настройка окружения

```bash
# Создайте .env файл из примера
cp .env.example .env

# ВАЖНО: Измените JWT_SECRET в .env на свой ключ (минимум 32 символа)
nano .env
```

### 2. Запуск базы данных
```
# Запустить Docker desctop
# скачать первый образ PostgreSQL

docker pull postgres

```bash
# Запустите PostgreSQL в Docker  
docker-compose up -d  
# time="2026-06-15T22:03:16+03:00" level=warning msg="\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"  

# Проверьте, что БД запустилась  
docker-compose ps  
```
ображение списка контейнеров, управляемых файлом docker-compose.yml.   
• Список контейнеров: все контейнеры (имена), которые были созданы с помощью docker-compose up, включая их статус (запущен, остановлен и т.д.).  
• Информация о портах: Указывает, какие порты проброшены на хост-машину.  
  
NAME                IMAGE                COMMAND                  SERVICE    CREATED         STATUS                   PORTS  
secure_service_db   postgres:15-alpine   "docker-entrypoint.s…"   postgres   8 minutes ago   Up 8 minutes (healthy)   0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp  

*) Убедитесь, что база данных secure_service действительно создана.  
Вы можете подключиться к вашему контейнеру PostgreSQL и выполнить sql-команду:  \l  

docker exec -it secure_service_db psql -U postgres  
postgres=# \l  
postgres=# \q  
```txt

                                                   List of databases
      Name      |  Owner   | Encoding |  Collate   |   Ctype    | ICU Locale | Locale Provider |   Access privileges  
----------------+----------+----------+------------+------------+------------+-----------------+-----------------------  
 postgres       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            |  
 secure_service | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            |  
 template0      | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +  
                |          |          |            |            |            |                 | postgres=CTc/postgres  
 template1      | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +  

                |          |          |            |            |            |                 | postgres=CTc/postgres  

```txt
Убедитесь, что пользователь postgres имеет необходимые права доступа к базе данных "secure_service".   
Вы можете проверить права доступа следующим образом:  
postgres=# \du  
```txt
                                   List of roles  
 Role name |                         Attributes                         | Member of  
-----------+------------------------------------------------------------+-----------  
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}  

```txt
Если у пользователя нет необходимых прав, вы можете предоставить их:  
GRANT ALL PRIVILEGES ON DATABASE secure_service TO postgres;  
проверить подключение к базе данных с использованием командной строки:  
psql -h localhost -U postgres -d secure_service  
```txt

для выхода из командной строки psql (PostgreSQL) : \q  

#### *. Проблемы с БД 
   перезапустить все контейнеры: docker-compose up -d
   Если изменили файл docker-compose.yml и хотите применить изменения (обновить конфигурацию): docker-compose up -d --build
### 3. Установка зависимостей

```bash
# Скачайте Go модули
go mod download
```

### 4. Что нужно реализовать

Все файлы с пометкой TODO содержат заготовки функций, которые нужно завершить:

#### 📄 `database.go` - Работа с базой данных
- [ ] `CreateUser()` - создание пользователя
- [ ] `GetUserByEmail()` - поиск по email
- [ ] `GetUserByID()` - поиск по ID
- [ ] `UserExistsByEmail()` - проверка существования

#### 🔐 `auth.go` - Аутентификация и безопасность
- [ ] `HashPassword()` - хеширование паролей bcrypt
- [ ] `CheckPassword()` - проверка паролей
- [ ] `GenerateToken()` - создание JWT токенов
- [ ] `ValidateToken()` - проверка JWT токенов

#### 🛡️ `middleware.go` - Защита эндпоинтов
- [ ] `AuthMiddleware()` - проверка токенов

#### 🌐 `handlers.go` - HTTP обработчики
- [ ] `RegisterHandler()` - регистрация
- [ ] `LoginHandler()` - авторизация
- [ ] `ProfileHandler()` - профиль пользователя

## 📝 Пошаговое руководство

### Шаг 1: Реализуйте функции безопасности (`auth.go`)

```go
// Импортируйте необходимые пакеты
import (
    "golang.org/x/crypto/bcrypt"
    "github.com/golang-jwt/jwt/v5"
)

// Реализуйте HashPassword
func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}
```

### Шаг 2: Реализуйте работу с БД (`database.go`)

```go
// ВАЖНО: Используйте параметризованные запросы!
func CreateUser(email, username, passwordHash string) (*User, error) {
    query := `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at`
    // Реализуйте...
}
```

### Шаг 3: Реализуйте middleware (`middleware.go`)

```go
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Получите токен из заголовка Authorization
        // 2. Проверьте формат "Bearer <token>"
        // 3. Валидируйте токен
        // 4. Добавьте данные в контекст
        // 5. Передайте управление дальше
    }
}
```

### Шаг 4: Реализуйте обработчики (`handlers.go`)

Каждый обработчик содержит детальные комментарии с пошаговыми инструкциями.

### Шаг 5: Запустите и протестируйте

```bash
# Запустите сервер
go run *.go

# В другом терминале тестируйте API
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"SecurePass123"}'
```

## 🧪 Тестирование API

### 1. Проверка здоровья сервиса
```bash
curl http://localhost:8080/health
```

### 2. Регистрация пользователя
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "SecurePass123"
  }'
```

### 3. Вход в систему
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123"
  }'
```

### 4. Получение профиля (с токеном)
```bash
# Замените YOUR_JWT_TOKEN на токен из ответа /login
curl http://localhost:8080/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔒 Требования безопасности

### ✅ Обязательные требования:

1. **Пароли хешируются bcrypt**
   ```go
   // ❌ НЕПРАВИЛЬНО
   user.Password = password

   // ✅ ПРАВИЛЬНО
   hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
   ```

2. **SQL запросы параметризованы**
   ```go
   // ❌ ОПАСНО - SQL инъекции!
   query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)

   // ✅ БЕЗОПАСНО
   query := "SELECT * FROM users WHERE email = $1"
   db.QueryRow(query, email)
   ```

3. **JWT токены проверяются**
   ```go
   // ❌ БЕЗ ПРОВЕРКИ
   func ProfileHandler(w http.ResponseWriter, r *http.Request) {
       // Сразу возвращаем данные
   }

   // ✅ С ПРОВЕРКОЙ
   http.HandleFunc("/profile", AuthMiddleware(ProfileHandler))
   ```

## 🐛 Частые ошибки

### 1. Пароли в открытом виде
```sql
-- ❌ ПЛОХО: пароль не захеширован
SELECT password_hash FROM users; -- "123456"

-- ✅ ХОРОШО: bcrypt хеш
-- "$2a$10$N9qo8uLOickgx2ZMRZoMye..."
```

### 2. SQL инъекции
```go
// ❌ УЯЗВИМО
query := "SELECT * FROM users WHERE email = '" + email + "'"

// ✅ ЗАЩИЩЕНО
query := "SELECT * FROM users WHERE email = $1"
db.QueryRow(query, email)
```

### 3. JWT не проверяется
```go
// ❌ ОПАСНО
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
    // Нет проверки токена!
}

// ✅ БЕЗОПАСНО
http.HandleFunc("/profile", AuthMiddleware(ProfileHandler))
```

## ✅ Чек-лист перед сдачей

- [✔] PostgreSQL запускается через `docker-compose up`
- [ ] Приложение подключается к БД и не падает
- [ ] Регистрация создает пользователя в БД
- [ ] Пароли хранятся как bcrypt хеш, НЕ в открытом виде
- [ ] Вход возвращает валидный JWT токен
- [ ] Токен можно декодировать на https://jwt.io
- [ ] Эндпоинт `/profile` требует токен (без токена → 401)
- [ ] Эндпоинт `/profile` работает с правильным токеном
- [✔] **ВСЕ** SQL запросы используют параметры `$1, $2...`
- [✔] В коде НЕТ `fmt.Sprintf` для построения SQL

## 🔍 Проверка безопасности

### Проверьте хеширование паролей:
```bash
# Подключитесь к БД
docker exec -it secure_service_db psql -U postgres -d secure_service

# Проверьте хеши паролей
SELECT email, password_hash FROM users;

# Хеш должен начинаться с $2a$ или $2b$
\q  
```

### Проверьте JWT токен:
1. Скопируйте токен из ответа `/login`
2. Вставьте на https://jwt.io
3. Убедитесь, что содержит `user_id`, `email`, `username`

## 🆘 Получение помощи

### Если что-то не работает:

1. **БД не запускается**
   ```bash
   docker-compose down
   docker-compose up -d
   docker-compose logs postgres
   ```
2. **Ошибки компиляции**
   ```bash
   go mod tidy
   go mod download
   ```
3. **Сервер не запускается**
   - Проверьте .env файл
   - Убедитесь, что JWT_SECRET длиннее 32 символов
   - Проверьте, что PostgreSQL запущен

4. **Тесты API не проходят**
   - Проверьте логи сервера
   - Убедитесь, что все TODO функции реализованы
   - Проверьте правильность JSON в curl запросах

## 🎯 Критерии оценки

### "Зачёт" - все требования выполнены:
- ✅ Регистрация и авторизация работают
- ✅ Пароли хешируются bcrypt
- ✅ JWT токены используются правильно
- ✅ SQL запросы параметризованы
- ✅ Защищенные эндпоинты требуют токен
- ✅ Код компилируется и запускается

### "На доработку":
- ❌ Пароли в открытом виде
- ❌ SQL инъекции возможны
- ❌ JWT не проверяются
- ❌ Код не компилируется
```

curl http://localhost:8080/health  
{"message":"Service is running","status":"ok"}  
  
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d "{ \"email\": \"test@example.com\", \"password\": \"SecurePass123\" }"  
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzgxNjk3MDgzLCJpYXQiOjE3ODE2MTA2ODN9.qX29O1uNGEAvyZX-C6i3_kyDj1fXgYVbcyZmjpCbByI","user": {"email":"test@example.com","id":1}}  

curl http://localhost:8080/profile -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzgxNjk3MDgzLCJpYXQiOjE3ODE2MTA2ODN9.  qX29O1uNGEAvyZX-C6i3_kyDj1fXgYVbcyZmjpCbByI" 

curl http://localhost:8080/profile -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzgxNjk3MDgzLCJpYXQiOjE3ODE2MTA2ODN9. qX29O1uNGEAvyZX-C6i3_kyDj1fXgYVbcyZmjpCbByI"  
{"id":1,"email":"test@example.com","username":"testuser","created_at":"2026-06-15T20:37:36.378345Z"}  

![результат теста]](doc/screenshots/test.png)