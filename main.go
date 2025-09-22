package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"backend/graph/generated"
	"backend/internal/auth"
	"backend/internal/handlers"
	"backend/internal/resolvers"
	"backend/internal/services"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

func debugTokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 Debug token endpoint called")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("❌ No Authorization header in debug request")
		http.Error(w, "No Authorization header", http.StatusBadRequest)
		return
	}

	log.Printf("🔍 Debug - Auth header: %s...", authHeader[:min(30, len(authHeader))])

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		log.Printf("❌ Debug - Missing Bearer prefix")
		http.Error(w, "Missing Bearer prefix", http.StatusBadRequest)
		return
	}

	claims, err := auth.ValidateToken(tokenString)
	if err != nil {
		log.Printf("❌ Debug - Token validation failed: %v", err)
		http.Error(w, fmt.Sprintf("Token validation failed: %v", err), http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Debug - Token validated successfully")

	response := map[string]interface{}{
		"valid": true,
		"claims": map[string]interface{}{
			"user_id": claims.UserID,
			"email":   claims.Email,
			"role":    claims.Role,
			"expires": claims.ExpiresAt,
			"issued":  claims.IssuedAt,
		},
		"message": "Token is valid",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

	json.NewEncoder(w).Encode(response)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func selectiveAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the request body to check the operation
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("❌ Failed to read request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Restore the body for the next handler
		r.Body = io.NopCloser(strings.NewReader(string(body)))

		// Parse the GraphQL request
		var gqlRequest struct {
			Query string `json:"query"`
		}

		if err := json.Unmarshal(body, &gqlRequest); err != nil {
			log.Printf("❌ Failed to parse GraphQL request: %v", err)
			http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
			return
		}

		// Check if this is a public operation (login or register)
		query := strings.ToLower(strings.TrimSpace(gqlRequest.Query))

		isLoginMutation := strings.Contains(query, "mutation") && strings.Contains(query, "login(")
		isRegisterMutation := strings.Contains(query, "mutation") && strings.Contains(query, "register(")

		if isLoginMutation || isRegisterMutation {
			log.Printf("🔓 Public operation detected (%s), skipping auth",
				func() string {
					if isLoginMutation {
						return "login"
					}
					return "register"
				}())
			next.ServeHTTP(w, r)
			return
		}

		// For all other operations, require authentication
		log.Printf("🔐 Protected operation detected, applying auth middleware")
		auth.AuthMiddleware(next).ServeHTTP(w, r)
	})
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Database connection
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		// Use a default for local development
		dbURL = "postgres://postgres:postgres@localhost:5432/file_manager?sslmode=disable"
		log.Printf("⚠️ DB_URL not set, using default: %s", dbURL)
	}

	database, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Test connection
	if err := database.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Run database migrations
	if err := runMigrations(database); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize services
	s3Service, err := services.NewS3Service()
	if err != nil {
		log.Printf("❌ Failed to initialize S3 service: %v", err)
		log.Printf("⚠️ Uploads will not work without S3 service")
		// Don't exit - continue without S3 service for now
		s3Service = nil
	} else {
		log.Printf("✅ S3 service initialized successfully")
	}

	// Initialize encryption service with proper parameters
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		encryptionKey = "default-development-key-32-bytes!!" // 32 bytes for AES-256
		log.Printf("⚠️ Using default encryption key - set ENCRYPTION_KEY env var in production")
	}

	encryptionService := services.NewEncryptionService(encryptionKey)
	if encryptionService == nil {
		log.Printf("❌ Failed to initialize encryption service")
		log.Printf("⚠️ Encryption features will not work")
	} else {
		log.Printf("✅ Encryption service initialized successfully")
	}

	// Initialize resolver with encryption service
	resolver := resolvers.NewResolver(database, s3Service, encryptionService)

	// Initialize upload handler - only if S3 service is available
	var uploadHandler *handlers.UploadHandler
	if s3Service != nil {
		uploadHandler = handlers.NewUploadHandler(database, s3Service, encryptionService)
		log.Printf("✅ Upload handler initialized")
	} else {
		log.Printf("⚠️ Upload handler not initialized - S3 service unavailable")
	}

	// Initialize download handler - only if S3 service is available
	var downloadHandler *handlers.DownloadHandler
	if s3Service != nil && encryptionService != nil {
		downloadHandler = handlers.NewDownloadHandler(database, s3Service, encryptionService)
		log.Printf("✅ Download handler initialized")
	} else {
		log.Printf("⚠️ Download handler not initialized - S3 service or encryption service unavailable")
	}

	// Create GraphQL server WITHOUT auth middleware
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{
		Resolvers: resolver,
	}))

	// Setup router
	router := mux.NewRouter()

	// GraphQL endpoints - NO AUTH MIDDLEWARE
	router.Handle("/graphql", playground.Handler("GraphQL playground", "/query"))
	router.Handle("/query", selectiveAuthMiddleware(srv))

	log.Printf("✅ GraphQL endpoint (no global auth): /query")
	log.Printf("🎮 GraphQL playground: /graphql")

	// Initialize PUBLIC GraphQL handler
	publicGraphQLHandler := handlers.NewPublicGraphQLHandler(database, s3Service, encryptionService)

	// Add PUBLIC routes
	publicRoutes := router.PathPrefix("/public").Subrouter()
	publicRoutes.HandleFunc("/graphql", publicGraphQLHandler.HandlePublicGraphQL).Methods("POST", "OPTIONS")
	publicRoutes.HandleFunc("/graphql", publicGraphQLHandler.HandlePublicPlayground).Methods("GET")

	log.Printf("✅ Public GraphQL endpoint: /public/graphql")

	// File endpoints with authentication middleware - only if handlers are available
	if uploadHandler != nil {
		router.HandleFunc("/upload", auth.RequireAuthMiddleware(uploadHandler.HandleFileUpload)).Methods("POST", "OPTIONS")
		log.Printf("✅ Upload endpoint registered: /upload")
	} else {
		log.Printf("⚠️ Upload endpoint not registered - handler unavailable")
	}

	if downloadHandler != nil {
		router.HandleFunc("/download/{fileId}", auth.RequireAuthMiddleware(downloadHandler.HandleFileDownload)).Methods("GET", "OPTIONS")
		log.Printf("✅ Download endpoint registered: /download/{fileId}")

		// Add public download route for share tokens (no auth required)
		router.HandleFunc("/share/download/{shareToken}", downloadHandler.HandlePublicFileDownload).Methods("GET", "OPTIONS")
		log.Printf("✅ Public download endpoint registered: /share/download/{shareToken}")
	} else {
		log.Printf("⚠️ Download endpoint not registered - handler unavailable")
	}

	// Add a health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","services":{"database":"connected","s3":"` +
			func() string {
				if s3Service != nil {
					return "connected"
				}
				return "disconnected"
			}() + `","encryption":"` +
			func() string {
				if encryptionService != nil {
					return "connected"
				}
				return "disconnected"
			}() + `"}}`))
	}).Methods("GET")

	// Temporary admin creation endpoint (REMOVE IN PRODUCTION)
	router.HandleFunc("/create-admin", func(w http.ResponseWriter, r *http.Request) {
		// Hash the password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("❌ Failed to hash password: %v", err)
			http.Error(w, "Failed to create admin", http.StatusInternalServerError)
			return
		}

		// Insert admin user
		query := `
			INSERT INTO users (id, name, email, password_hash, role, quota_limit, quota_used, is_active, created_at, updated_at) 
			VALUES (gen_random_uuid(), 'System Administrator', 'admin@balkanid.com', $1, 'ADMIN', 1073741824, 0, true, NOW(), NOW())
			ON CONFLICT (email) DO UPDATE SET role = 'ADMIN', password_hash = $1`

		_, err = database.Exec(query, string(passwordHash))
		if err != nil {
			log.Printf("❌ Failed to create admin user: %v", err)
			http.Error(w, "Failed to create admin", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"Admin user created successfully","email":"admin@balkanid.com","password":"admin123"}`))
		log.Printf("✅ Admin user created: admin@balkanid.com / admin123")
	}).Methods("POST")

	// Add debug endpoint
	router.HandleFunc("/debug/token", debugTokenHandler).Methods("GET", "POST")

	// Setup CORS with more permissive settings for development
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:5173",
			"http://localhost:5174",
			"http://localhost:5175",
			"http://localhost:5176",
			"http://localhost:3000",
			"http://127.0.0.1:5173",
			"http://127.0.0.1:5174",
			"http://127.0.0.1:5175",
			"http://127.0.0.1:5176",
			"http://127.0.0.1:3000",
		},
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Authorization",
			"Content-Type",
			"Accept",
			"Origin",
			"X-Requested-With",
		},
		AllowedMethods: []string{
			"GET",
			"POST",
			"PUT",
			"DELETE",
			"OPTIONS",
		},
		ExposedHeaders: []string{
			"Content-Length",
			"Content-Type",
		},
		MaxAge: 86400, // 24 hours
	})

	// Apply CORS to the router
	httpHandler := c.Handler(router)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("📊 GraphQL Playground: http://localhost:%s/graphql", port)
	log.Printf("🔍 GraphQL API: http://localhost:%s/query", port)
	log.Printf("🔍 Public GraphQL API: http://localhost:%s/public/graphql", port)
	log.Printf("🏥 Health Check: http://localhost:%s/health", port)

	if uploadHandler != nil {
		log.Printf("📤 File Uploads: http://localhost:%s/upload", port)
	}
	if downloadHandler != nil {
		log.Printf("📥 File Downloads: http://localhost:%s/download/{fileId}", port)
	}

	log.Printf("✅ All services initialized successfully")
	log.Fatal(http.ListenAndServe(":"+port, httpHandler))
}

func runMigrations(db *sql.DB) error {
	log.Println("🔄 Running database migrations...")

	// Read the migration file
	content, err := ioutil.ReadFile("internal/db/migrations.sql")
	if err != nil {
		return fmt.Errorf("failed to read migrations.sql: %v", err)
	}

	// Execute the migration
	_, err = db.Exec(string(content))
	if err != nil {
		return fmt.Errorf("failed to execute migration: %v", err)
	}

	log.Println("✅ Database migrations completed successfully")
	return nil
}
