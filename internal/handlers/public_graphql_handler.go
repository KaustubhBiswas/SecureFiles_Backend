package handlers

import (
	"context"
	"database/sql"
	"net/http"

	"backend/graph/generated"
	"backend/internal/resolvers"
	"backend/internal/services"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
)

type PublicGraphQLHandler struct {
	db     *sql.DB
	server *handler.Server
}

func NewPublicGraphQLHandler(db *sql.DB, s3Service *services.S3Service, encryptionService *services.EncryptionService, folderService *services.FolderService, baseURL string, frontendURL string) *PublicGraphQLHandler {
	// Create resolver with correct fields - matching your existing resolver.go
	resolver := resolvers.NewResolver(db, s3Service, encryptionService, folderService, baseURL, frontendURL)

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{
		Resolvers: resolver,
	}))

	return &PublicGraphQLHandler{
		db:     db,
		server: srv,
	}
}

// HandlePublicGraphQL serves GraphQL queries for public access - FIXED to use http.Handler
func (h *PublicGraphQLHandler) HandlePublicGraphQL(w http.ResponseWriter, r *http.Request) {
	// Set public context - no user authentication
	ctx := context.WithValue(r.Context(), "isPublic", true)
	r = r.WithContext(ctx)

	// Set CORS headers for public access
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	h.server.ServeHTTP(w, r)
}

// HandlePublicPlayground serves GraphQL playground for public queries - FIXED to use http.Handler
func (h *PublicGraphQLHandler) HandlePublicPlayground(w http.ResponseWriter, r *http.Request) {
	playground.Handler("GraphQL Public Playground", "/public/graphql").ServeHTTP(w, r)
}
