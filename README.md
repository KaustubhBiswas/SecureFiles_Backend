# File Storage Backend with GraphQL API

A secure file storage backend built with Go, GraphQL, PostgreSQL, and Backblaze B2 (S3-compatible). Features include file encryption, deduplication, user authentication, quota management, and presigned URL uploads.

## 🚀 Features

- **Secure File Storage**: Files are encrypted before storing in Backblaze B2
- **File Deduplication**: Identical files share storage space
- **User Authentication**: JWT-based authentication system  
- **Quota Management**: Track and limit user storage usage
- **Presigned URLs**: Direct B2 uploads with temporary URLs
- **GraphQL API**: Modern API with type-safe queries and mutations
- **Rate Limiting**: Protection against API abuse
- **File Downloads**: Secure downloads with decryption

## 📁 Project Structure

```
backend/
├── .env                        # Environment variables (not tracked)
├── .gitignore                  # Git ignore file
├── docker-compose.yml          # Docker composition for development
├── dockerfile                  # Docker container configuration
├── go.mod                      # Go module dependencies
├── go.sum                      # Go module checksums
├── gqlgen.yml                  # GraphQL code generation config
├── main.go                     # Application entry point
├── server                      # Compiled binary
├── graph/                      # GraphQL schema and resolvers
│   ├── resolver.go            # Root resolver
│   ├── schema.graphqls        # GraphQL schema definition
│   ├── schema.resolvers.go    # Generated resolvers
│   ├── generated/             # Auto-generated GraphQL code
│   └── model/                 # GraphQL models
├── internal/                   # Private application code
│   ├── auth/                  # Authentication logic
│   ├── db/                    # Database migrations
│   ├── handlers/              # HTTP handlers
│   ├── middleware/            # HTTP middleware
│   ├── resolvers/             # GraphQL resolvers implementation
│   └── services/              # Business logic services
└── uploadfiles/               # Local file uploads (development only)
```

## 🛠 Prerequisites

- **Go 1.19+**
- **PostgreSQL 12+**
- **Backblaze B2 Bucket (S3-compatible)**
- **Docker** (optional)

## ⚙️ Environment Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Install Go dependencies:**
   ```bash
   go mod download
   ```

3. **Set up environment variables:**
   Create a `.env` file in the backend directory:
   ```env
   # Database Configuration
   DB_URL="postgresql://username:password@localhost:5432/database"
   DB_PORT=5432
   DB_USER=postgres
   DB_PASSWORD=your_password
   DB_NAME=file_storage
   
   # JWT Configuration
   JWT_SECRET="your-super-secret-jwt-key-here"
   
   # Encryption
   ENCRYPTION_MASTER_KEY="your-32-byte-base64-encryption-key"
   
  # Backblaze B2 Configuration (S3-compatible)
  STORAGE_PROVIDER=b2
  B2_S3_ENDPOINT=https://s3.<region>.backblazeb2.com
  B2_BUCKET_NAME=your-b2-bucket
  B2_KEY_ID=your_b2_key_id
  B2_APPLICATION_KEY=your_b2_application_key
  B2_REGION=<region>
   
   # Server Configuration
   PORT=8080
   ```

4. **Generate encryption key:**
   ```bash
   # Using PowerShell
   $bytes = New-Object byte[] 32
   [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
   [Convert]::ToBase64String($bytes)
   
   # Or using Go
   go run -c 'package main; import ("crypto/rand"; "encoding/base64"; "fmt"); func main() { key := make([]byte, 32); rand.Read(key); fmt.Println(base64.StdEncoding.EncodeToString(key)) }'
   ```

5. **Set up PostgreSQL database:**
   ```sql
   CREATE DATABASE file_storage;
   ```

6. **Run database migrations:**
   ```bash
   # Apply the SQL migrations from internal/db/migrations.sql
   psql -d file_storage -f internal/db/migrations.sql
   ```

## 🚀 Running the Application

### Development Mode

```bash
# Run directly with Go
go run main.go

# Or build and run
go build -o server main.go
./server
```

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run in background
docker-compose up -d
```

The server will start on `http://localhost:8080`

**Available Endpoints:**
- GraphQL Playground: `http://localhost:8080/graphql`
- GraphQL API: `http://localhost:8080/query`
- File Downloads: `http://localhost:8080/download/{fileId}`

## 🧪 Testing with GraphQL Playground

Open `http://localhost:8080/graphql` in your browser to access the GraphQL playground.

### Authentication

First, you need to authenticate to get a JWT token:

```graphql
# Register a new user
mutation RegisterUser {
  register(input: {
    username: "testuser"
    email: "test@example.com"
    password: "securepassword123"
  }) {
    token
    user {
      id
      username
      email
      role
    }
  }
}

# Or login with existing credentials
mutation LoginUser {
  login(input: {
    email: "test@example.com"
    password: "securepassword123"
  }) {
    token
    user {
      id
      username
      email
      role
    }
  }
}
```

**Set Authorization Header:**
After getting the token, add it to the HTTP Headers in GraphQL Playground:
```json
{
  "Authorization": "Bearer YOUR_JWT_TOKEN_HERE"
}
```

### File Upload Flow

#### 1. Request Upload URL
```graphql
mutation RequestUpload {
  requestUpload(input: {
    filename: "document.pdf"
    mimeType: "application/pdf"
    isPublic: false
    description: "My important document"
    tags: ["work", "important"]
  }) {
    uploadId
    uploadUrl
    expiresAt
    maxFileSize
  }
}
```

#### 2. Upload File (via HTTP PUT - outside GraphQL)
```bash
# Use the uploadUrl from step 1
curl -X PUT "UPLOAD_URL_FROM_STEP_1" \
  --data-binary @"your-file.pdf" \
  -H "Content-Type: application/pdf"
```

#### 3. Confirm Upload
```graphql
mutation ConfirmUpload {
  confirmUpload(uploadId: "UPLOAD_ID_FROM_STEP_1") {
    id
    filename
    originalFilename
    size
    mimeType
    isPublic
    description
    tags
    downloadCount
    createdAt
    updatedAt
  }
}
```

### File Management Queries

#### List User Files
```graphql
query ListFiles {
  files(limit: 10, offset: 0) {
    nodes {
      id
      filename
      originalFilename
      size
      mimeType
      isPublic
      downloadCount
      tags
      createdAt
    }
    totalCount
    hasNextPage
  }
}
```

#### Get Single File
```graphql
query GetFile {
  file(id: "file-id-here") {
    id
    filename
    size
    mimeType
    isPublic
    description
    tags
    downloadCount
    createdAt
    updatedAt
  }
}
```

#### Get Download URL
```graphql
query GetDownloadUrl {
  downloadFile(id: "file-id-here") {
    downloadUrl
    filename
    size
    expiresAt
  }
}
```

### User & Quota Management

#### Get User Profile
```graphql
query UserProfile {
  me {
    id
    username
    email
    role
    quotaUsed
    quotaLimit
    createdAt
  }
}
```

#### Check Quota Usage
```graphql
query QuotaUsage {
  quotaInfo {
    used
    limit
    available
    percentUsed
  }
}
```

### File Operations

#### Update File Metadata
```graphql
mutation UpdateFile {
  updateFile(
    id: "file-id-here"
    input: {
      filename: "new-filename.pdf"
      description: "Updated description"
      isPublic: true
      tags: ["updated", "public"]
    }
  ) {
    id
    filename
    description
    isPublic
    tags
    updatedAt
  }
}
```

#### Delete File
```graphql
mutation DeleteFile {
  deleteFile(id: "file-id-here") {
    success
    message
  }
}
```

### Folder Management

#### Create Folder
```graphql
mutation CreateFolder {
  createFolder(input: {
    name: "Documents"
    description: "My document folder"
    isPublic: false
  }) {
    id
    name
    description
    isPublic
    fileCount
    createdAt
  }
}
```

#### List Folders
```graphql
query ListFolders {
  folders {
    id
    name
    description
    isPublic
    fileCount
    createdAt
  }
}
```

## 🧪 Testing with curl

### Complete Upload and Download Test
```bash
# Set your JWT token
JWT_TOKEN="your-jwt-token-here"

# 1. Request upload
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"query":"mutation { requestUpload(input: { filename: \"test.pdf\", mimeType: \"application/pdf\", isPublic: false }) { uploadId uploadUrl expiresAt } }"}'

# 2. Upload file (use uploadUrl from step 1)
curl -X PUT "PRESIGNED_URL_HERE" \
  --data-binary @"test.pdf" \
  -H "Content-Type: application/pdf"

# 3. Confirm upload (use uploadId from step 1)
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"query":"mutation { confirmUpload(uploadId: \"UPLOAD_ID_HERE\") { id filename size } }"}'

# 4. Download file (use file id from step 3)
curl -H "Authorization: Bearer $JWT_TOKEN" \
  -o "downloaded.pdf" \
  "http://localhost:8080/download/FILE_ID_HERE"
```

## 🐛 Troubleshooting

### Common Issues

1. **"Database connection failed"**
   - Check PostgreSQL is running
   - Verify DB_URL in .env file
   - Ensure database exists

2. **"B2 operation failed"**
  - Verify B2 key ID and application key
  - Check the B2 bucket exists and is accessible
  - Confirm B2 endpoint and region settings

3. **"Encryption service not available"**
   - Ensure ENCRYPTION_MASTER_KEY is set in .env
   - Verify the key is base64 encoded and 32 bytes

4. **"Authentication required"**
   - Include Authorization header with valid JWT
   - Token may have expired, get a new one

### Debug Mode
```bash
# Run with verbose logging
go run main.go --debug
```

### Database Reset
```bash
# Drop and recreate database
psql -c "DROP DATABASE file_storage;"
psql -c "CREATE DATABASE file_storage;"
psql -d file_storage -f internal/db/migrations.sql
```

## 🔧 Development

### Generate GraphQL Code
```bash
go run github.com/99designs/gqlgen generate
```

### Run Tests
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific service tests
go test ./internal/services/
```


## 📝 Complete API Documentation

### 🔗 GraphQL Endpoints

- **GraphQL Playground**: `http://localhost:8080/graphql` (Development)
- **GraphQL API**: `http://localhost:8080/query`
- **Public API**: `http://localhost:8080/public/query` (No auth required)

### 🔐 Authentication

All authenticated requests require a JWT token in the `Authorization` header:
```
Authorization: Bearer YOUR_JWT_TOKEN_HERE
```

---

## 🏗️ API Schema Overview

### Query Operations

#### **User & Authentication**
```graphql
type Query {
  # Get current authenticated user
  me: User!
  
  # Get quota usage information
  quotaUsage: QuotaInfo!
}
```

#### **File & Folder Management**
```graphql
type Query {
  # List user's files with pagination
  files(folderId: ID, limit: Int, offset: Int): FileConnection!
  
  # Get single file by ID
  file(id: ID!): File!
  
  # List folders (optionally by parent)
  folders(parentId: ID): [Folder!]!
  
  # Get download URL for file
  downloadFile(id: ID!): DownloadInfo!
}
```

#### **Public Access (No Auth Required)**
```graphql
type Query {
  # Get public file by share token
  publicFile(shareToken: String!): File!
  
  # Get public download URL
  publicDownload(shareToken: String!): DownloadInfo!
}
```

#### **Admin-Only Queries** (Requires ADMIN role)
```graphql
type Query {
  # List all files across all users
  adminAllFiles(limit: Int, offset: Int): AdminFileConnection!
  
  # List all users
  adminAllUsers(limit: Int, offset: Int): AdminUserConnection!
  
  # Get system statistics
  adminStats: AdminStats!
  
  # Get files for specific user
  adminUserFiles(userId: ID!, limit: Int, offset: Int): FileConnection!
}
```

### Mutation Operations

#### **Authentication**
```graphql
type Mutation {
  # User login
  login(email: String!, password: String!): AuthResponse!
  
  # User registration
  register(input: RegisterInput!): AuthResponse!
}
```

#### **File Operations**
```graphql
type Mutation {
  # Step 1: Request upload URL
  requestUpload(input: UploadRequestInput!): UploadResponse!
  
  # Step 2: Confirm upload completion
  confirmUpload(uploadId: ID!): File!
  
  # Delete user's file
  deleteFile(id: ID!): DeleteResponse!
  
  # Toggle file public/private visibility
  toggleFileVisibility(id: ID!): File!
  
  # Generate shareable link for file
  generateShareLink(fileID: String!, expiresIn: Int): ShareLinkResponse!
  
  # Update file metadata
  updateFile(id: ID!, input: UpdateFileInput!): File!
}
```

#### **Folder Operations**
```graphql
type Mutation {
  # Create new folder
  createFolder(name: String!, parentId: ID): Folder!
}
```

#### **Admin-Only Mutations** (Requires ADMIN role)
```graphql
type Mutation {
  # Delete any file
  adminDeleteFile(fileId: ID!): DeleteResponse!
  
  # Toggle user active/inactive status
  adminToggleUserStatus(userId: ID!): User!
  
  # Update user quota limit
  adminUpdateUserQuota(userId: ID!, newQuota: Int!): User!
}
```

---

## 📊 GraphQL Types & Schemas

### Core Types

#### **User Type**
```graphql
type User {
  id: ID!                    # Unique user identifier
  name: String!              # Full name
  email: String!             # Email address (unique)
  role: String!              # USER or ADMIN
  quotaUsed: Int!            # Storage used in bytes
  quotaLimit: Int!           # Storage limit in bytes
  isActive: Boolean!         # Account status
  createdAt: Time!           # Account creation timestamp
}
```

#### **File Type**
```graphql
type File {
  id: ID!                    # Unique file identifier
  filename: String!          # Current filename
  originalFilename: String!  # Original upload filename
  size: Int!                 # File size in bytes
  mimeType: String!          # MIME type (e.g., application/pdf)
  isPublic: Boolean!         # Public visibility flag
  description: String        # Optional description
  tags: [String!]!           # Array of tags
  downloadCount: Int!        # Number of downloads
  createdAt: Time!           # Upload timestamp
  updatedAt: Time!           # Last modification timestamp
}
```

#### **Folder Type**
```graphql
type Folder {
  id: ID!                    # Unique folder identifier
  name: String!              # Folder name
  createdAt: Time!           # Creation timestamp
}
```

#### **QuotaInfo Type**
```graphql
type QuotaInfo {
  used: Int!                 # Bytes used
  limit: Int!                # Byte limit
  percentage: Float!         # Usage percentage (0-100)
  files: Int!                # Number of files
}
```

### Response Types

#### **AuthResponse**
```graphql
type AuthResponse {
  token: String!             # JWT token for authentication
  user: User!                # User information
}
```

#### **UploadResponse**
```graphql
type UploadResponse {
  uploadId: ID!              # Upload session identifier
  uploadUrl: String!         # Presigned B2 URL for upload
  expiresAt: Time!           # URL expiration time
  maxFileSize: Int!          # Maximum allowed file size
}
```

#### **DownloadInfo**
```graphql
type DownloadInfo {
  downloadUrl: String!       # Presigned download URL
  expiresAt: Time!           # URL expiration time
  filename: String!          # Original filename
  size: Int!                 # File size in bytes
}
```

#### **ShareLinkResponse**
```graphql
type ShareLinkResponse {
  shareToken: String!        # Public share token
  shareUrl: String!          # Complete shareable URL
  expiresAt: Time            # Optional expiration time
  isActive: Boolean!         # Link status
}
```

#### **FileConnection** (Pagination)
```graphql
type FileConnection {
  nodes: [File!]!            # Array of files
  totalCount: Int!           # Total files available
  hasNextPage: Boolean!      # More results available
}
```

### Input Types

#### **RegisterInput**
```graphql
input RegisterInput {
  name: String!              # Full name (required)
  email: String!             # Email address (required, unique)
  password: String!          # Password (min 8 characters)
}
```

#### **UploadRequestInput**
```graphql
input UploadRequestInput {
  filename: String!          # Desired filename
  mimeType: String!          # File MIME type
  folderId: ID               # Optional folder ID
  description: String        # Optional description
  tags: [String!]            # Optional tags array
  isPublic: Boolean! = false # Public visibility (default: false)
}
```

#### **UpdateFileInput**
```graphql
input UpdateFileInput {
  description: String        # Update description
  tags: [String!]            # Update tags
  isPublic: Boolean          # Update visibility
}
```

### Admin-Specific Types

#### **AdminFile Type**
```graphql
type AdminFile {
  # Standard file fields
  id: ID!
  filename: String!
  originalFilename: String!
  size: Int!
  mimeType: String!
  isPublic: Boolean!
  description: String
  tags: [String!]!
  downloadCount: Int!
  createdAt: Time!
  updatedAt: Time!
  
  # Admin-only fields
  owner: User!               # File owner information
  totalDownloads: Int!       # Global download count
  lastDownloadAt: Time       # Most recent download timestamp
}
```

#### **AdminUser Type**
```graphql
type AdminUser {
  # Standard user fields
  id: ID!
  name: String!
  email: String!
  role: String!
  quotaUsed: Int!
  quotaLimit: Int!
  isActive: Boolean!
  createdAt: Time!
  
  # Admin-only fields
  fileCount: Int!            # Total files owned
  totalDownloads: Int!       # Total downloads across all files
  lastLoginAt: Time          # Most recent login timestamp
}
```

#### **AdminStats Type**
```graphql
type AdminStats {
  totalUsers: Int!           # Total registered users
  totalFiles: Int!           # Total files in system
  totalDownloads: Int!       # Total download count
  totalStorageUsed: Int!     # Total storage used (bytes)
  activeUsers: Int!          # Currently active users
  publicFiles: Int!          # Number of public files
  recentUploads: Int!        # Recent uploads (24h)
  recentDownloads: Int!      # Recent downloads (24h)
}
```

---

## 🔧 Complete API Examples

### Authentication Flow

#### Register New User
```graphql
mutation RegisterUser {
  register(input: {
    name: "John Doe"
    email: "john@example.com"
    password: "securepassword123"
  }) {
    token
    user {
      id
      name
      email
      role
      quotaUsed
      quotaLimit
      isActive
      createdAt
    }
  }
}
```

#### Login Existing User
```graphql
mutation LoginUser {
  login(
    email: "john@example.com"
    password: "securepassword123"
  ) {
    token
    user {
      id
      name
      email
      role
      quotaLimit
      quotaUsed
    }
  }
}
```

#### Get Current User Profile
```graphql
query MyProfile {
  me {
    id
    name
    email
    role
    quotaUsed
    quotaLimit
    isActive
    createdAt
  }
}
```

### File Upload Process

#### Step 1: Request Upload URL
```graphql
mutation RequestFileUpload {
  requestUpload(input: {
    filename: "important-document.pdf"
    mimeType: "application/pdf"
    description: "Project documentation"
    tags: ["work", "documentation", "project"]
    isPublic: false
    folderId: "folder-id-optional"
  }) {
    uploadId
    uploadUrl
    expiresAt
    maxFileSize
  }
}
```

#### Step 2: Upload File (HTTP PUT)
```bash
# Use the uploadUrl from Step 1
curl -X PUT "${UPLOAD_URL}" \
  --data-binary @"important-document.pdf" \
  -H "Content-Type: application/pdf"
```

#### Step 3: Confirm Upload
```graphql
mutation ConfirmFileUpload {
  confirmUpload(uploadId: "upload-id-from-step-1") {
    id
    filename
    originalFilename
    size
    mimeType
    isPublic
    description
    tags
    downloadCount
    createdAt
    updatedAt
  }
}
```

### File Management

#### List User Files with Pagination
```graphql
query ListMyFiles {
  files(limit: 20, offset: 0) {
    nodes {
      id
      filename
      originalFilename
      size
      mimeType
      isPublic
      description
      tags
      downloadCount
      createdAt
      updatedAt
    }
    totalCount
    hasNextPage
  }
}
```

#### Get Single File Details
```graphql
query GetFileDetails($fileId: ID!) {
  file(id: $fileId) {
    id
    filename
    originalFilename
    size
    mimeType
    isPublic
    description
    tags
    downloadCount
    createdAt
    updatedAt
  }
}
```

#### Update File Metadata
```graphql
mutation UpdateFileMetadata($fileId: ID!) {
  updateFile(
    id: $fileId
    input: {
      description: "Updated project documentation"
      tags: ["work", "documentation", "project", "updated"]
      isPublic: true
    }
  ) {
    id
    filename
    description
    tags
    isPublic
    updatedAt
  }
}
```

#### Toggle File Visibility
```graphql
mutation ToggleVisibility($fileId: ID!) {
  toggleFileVisibility(id: $fileId) {
    id
    filename
    isPublic
    updatedAt
  }
}
```

#### Generate Share Link
```graphql
mutation CreateShareLink($fileId: String!) {
  generateShareLink(
    fileID: $fileId
    expiresIn: 86400  # 24 hours in seconds
  ) {
    shareToken
    shareUrl
    expiresAt
    isActive
  }
}
```

#### Delete File
```graphql
mutation DeleteMyFile($fileId: ID!) {
  deleteFile(id: $fileId) {
    success
    message
  }
}
```

### File Download

#### Get Download URL
```graphql
query GetDownloadURL($fileId: ID!) {
  downloadFile(id: $fileId) {
    downloadUrl
    expiresAt
    filename
    size
  }
}
```

#### Direct Download (HTTP GET)
```bash
# Using the download URL from above
curl -H "Authorization: Bearer ${JWT_TOKEN}" \
  -o "downloaded-file.pdf" \
  "${DOWNLOAD_URL}"

# Or direct download endpoint
curl -H "Authorization: Bearer ${JWT_TOKEN}" \
  -o "file.pdf" \
  "http://localhost:8080/download/${FILE_ID}"
```

### Folder Management

#### Create Folder
```graphql
mutation CreateNewFolder {
  createFolder(
    name: "Project Documents"
    parentId: "parent-folder-id-optional"
  ) {
    id
    name
    createdAt
  }
}
```

#### List Folders
```graphql
query ListFolders {
  folders {
    id
    name
    createdAt
  }
}
```

#### List Files in Folder
```graphql
query FilesInFolder($folderId: ID!) {
  files(folderId: $folderId, limit: 50) {
    nodes {
      id
      filename
      size
      mimeType
      createdAt
    }
    totalCount
    hasNextPage
  }
}
```

### Public File Access (No Authentication)

#### Get Public File Info
```graphql
query GetPublicFile($shareToken: String!) {
  publicFile(shareToken: $shareToken) {
    id
    filename
    size
    mimeType
    description
    tags
    downloadCount
    createdAt
  }
}
```

#### Get Public Download URL
```graphql
query GetPublicDownload($shareToken: String!) {
  publicDownload(shareToken: $shareToken) {
    downloadUrl
    expiresAt
    filename
    size
  }
}
```

### Quota Management

#### Check Quota Usage
```graphql
query CheckQuota {
  quotaUsage {
    used
    limit
    percentage
    files
  }
}
```

### Admin Operations (ADMIN Role Required)

#### Get System Statistics
```graphql
query AdminDashboard {
  adminStats {
    totalUsers
    totalFiles
    totalDownloads
    totalStorageUsed
    activeUsers
    publicFiles
    recentUploads
    recentDownloads
  }
}
```

#### List All Users
```graphql
query AllUsers {
  adminAllUsers(limit: 50, offset: 0) {
    nodes {
      id
      name
      email
      role
      quotaUsed
      quotaLimit
      isActive
      createdAt
      fileCount
      totalDownloads
      lastLoginAt
    }
    totalCount
    hasNextPage
  }
}
```

#### List All Files
```graphql
query AllFiles {
  adminAllFiles(limit: 100, offset: 0) {
    nodes {
      id
      filename
      size
      mimeType
      isPublic
      downloadCount
      createdAt
      owner {
        id
        name
        email
      }
      totalDownloads
      lastDownloadAt
    }
    totalCount
    hasNextPage
  }
}
```

#### Update User Quota
```graphql
mutation UpdateUserQuota($userId: ID!, $newQuota: Int!) {
  adminUpdateUserQuota(userId: $userId, newQuota: $newQuota) {
    id
    name
    email
    quotaLimit
    quotaUsed
  }
}
```

#### Toggle User Status
```graphql
mutation ToggleUserStatus($userId: ID!) {
  adminToggleUserStatus(userId: $userId) {
    id
    name
    email
    isActive
  }
}
```

#### Delete Any File (Admin)
```graphql
mutation AdminDeleteFile($fileId: ID!) {
  adminDeleteFile(fileId: $fileId) {
    success
    message
  }
}
```

#### Get User's Files (Admin)
```graphql
query AdminUserFiles($userId: ID!) {
  adminUserFiles(userId: $userId, limit: 50, offset: 0) {
    nodes {
      id
      filename
      size
      mimeType
      isPublic
      downloadCount
      createdAt
    }
    totalCount
    hasNextPage
  }
}
```

---

## 🔍 Error Handling

### Common Error Responses

#### Authentication Errors
```json
{
  "errors": [
    {
      "message": "Authentication required",
      "extensions": {
        "code": "UNAUTHENTICATED"
      }
    }
  ]
}
```

#### Authorization Errors
```json
{
  "errors": [
    {
      "message": "Insufficient permissions",
      "extensions": {
        "code": "FORBIDDEN"
      }
    }
  ]
}
```

#### Validation Errors
```json
{
  "errors": [
    {
      "message": "File size exceeds quota limit",
      "extensions": {
        "code": "QUOTA_EXCEEDED"
      }
    }
  ]
}
```

#### Resource Not Found
```json
{
  "errors": [
    {
      "message": "File not found",
      "extensions": {
        "code": "NOT_FOUND"
      }
    }
  ]
}
```

---

## 🌐 HTTP REST Endpoints

### File Download Endpoint
```
GET /download/{fileId}
Authorization: Bearer {token}
```

### Public File Download
```
GET /public/download/{shareToken}
```

### Health Check
```
GET /health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "database": "connected",
  "b2": "connected"
}
```

---

## 📋 Rate Limits

- **General API**: 100 requests per minute per user
- **Upload requests**: 10 requests per minute per user  
- **Download requests**: 50 requests per minute per user
- **Admin operations**: 200 requests per minute

Rate limit headers included in responses:
- `X-RateLimit-Limit`: Request limit
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Reset timestamp

---

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **File Encryption**: All files encrypted at rest using AES-256
- **Access Control**: Role-based permissions (USER/ADMIN)
- **Rate Limiting**: Protection against API abuse
- **Presigned URLs**: Secure direct B2 uploads/downloads
- **Input Validation**: Comprehensive request validation
- **CORS Protection**: Configurable cross-origin policies

---

## 📚 Additional Resources

- **GraphQL Schema**: Complete schema in `graph/schema.graphqls`
- **Postman Collection**: [Download API collection](#)
- **Swagger/OpenAPI**: Available at `/docs` endpoint
- **Type Definitions**: Generated types in `graph/model/`