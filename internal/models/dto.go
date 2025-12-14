package models

// Auth DTOs

type RegisterRequest struct {
	Username  string  `json:"username" validate:"required,min=3,max=50"`
	Email     string  `json:"email" validate:"required,email"`
	Password  string  `json:"password" validate:"required,min=8"`
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,max=100"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,max=20"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	User         *User  `json:"user,omitempty"`
}

type UserResponse struct {
	User        *User    `json:"user"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// ============= USER MANAGEMENT DTOs =============

// CreateUserRequest DTO for admin creating a user
type CreateUserRequest struct {
	Username  string   `json:"username" validate:"required,min=3,max=50"`
	Email     string   `json:"email" validate:"required,email"`
	Password  string   `json:"password" validate:"required,min=8"`
	FirstName *string  `json:"first_name,omitempty"`
	LastName  *string  `json:"last_name,omitempty"`
	Phone     *string  `json:"phone,omitempty"`
	RoleIDs   []int64  `json:"role_ids,omitempty"`
}

// UpdateUserRequest DTO for updating a user
type UpdateUserRequest struct {
	Email     *string `json:"email,omitempty" validate:"omitempty,email"`
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Phone     *string `json:"phone,omitempty"`
}

// UserListItem DTO for user in list view
type UserListItem struct {
	ID              int64    `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	FirstName       *string  `json:"first_name,omitempty"`
	LastName        *string  `json:"last_name,omitempty"`
	IsActive        bool     `json:"is_active"`
	IsEmailVerified bool     `json:"is_email_verified"`
	Roles           []string `json:"roles,omitempty"`
	CreatedAt       string   `json:"created_at"`
}

// ListUsersResponse DTO for paginated user list
type ListUsersResponse struct {
	Users      []UserListItem `json:"users"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalCount int64          `json:"total_count"`
	TotalPages int            `json:"total_pages"`
}

// AssignRoleRequest DTO for assigning role
type AssignRoleRequest struct {
	RoleID int64 `json:"role_id" validate:"required"`
}
