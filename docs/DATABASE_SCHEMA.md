# Database Schema Documentation

## Overview
This document describes the complete database schema for the authentication and authorization system. The schema is designed to work with both PostgreSQL and Microsoft SQL Server.

## Entity Relationship Diagram

```
┌─────────────────────┐         ┌─────────────────────┐
│      roles          │         │   permissions       │
├─────────────────────┤         ├─────────────────────┤
│ PK  id              │         │ PK  id              │
│     name            │         │     name            │
│     description     │         │     resource        │
│     is_active       │         │     action          │
│     created_at      │         │     description     │
│     updated_at      │         │     created_at      │
└─────────┬───────────┘         └──────────┬──────────┘
          │                                │
          │         ┌────────────────┐     │
          └────────▶│role_permissions│◀────┘
                    ├────────────────┤
                    │ PK  id         │
                    │ FK  role_id    │
                    │ FK  permission_id │
                    │     assigned_at│
                    └────────────────┘

┌──────────────────────────┐
│        users             │
├──────────────────────────┤
│ PK  id                   │
│     username             │
│     email                │
│     password_hash        │
│     first_name           │
│     last_name            │
│     phone                │
│     is_active            │
│     is_email_verified    │
│     email_verified_at    │
│     last_login_at        │
│     password_changed_at  │
│     failed_login_attempts│
│     locked_until         │
│     created_at           │
│     updated_at           │
└──────────┬───────────────┘
           │
           │      ┌──────────────┐
           ├─────▶│ user_roles   │
           │      ├──────────────┤
           │      │ PK  id       │
           │      │ FK  user_id  │
           │      │ FK  role_id  │
           │      │     assigned_at │
           │      │     assigned_by │
           │      └──────────────┘
           │
           │      ┌──────────────────┐
           ├─────▶│ refresh_tokens   │
           │      ├──────────────────┤
           │      │ PK  id           │
           │      │ FK  user_id      │
           │      │     token        │
           │      │     expires_at   │
           │      │     is_revoked   │
           │      │     revoked_at   │
           │      │     ip_address   │
           │      │     user_agent   │
           │      │     created_at   │
           │      └──────────────────┘
           │
           │      ┌──────────────────┐
           └─────▶│ audit_logs       │
                  ├──────────────────┤
                  │ PK  id           │
                  │ FK  user_id      │
                  │     action       │
                  │     resource_type│
                  │     resource_id  │
                  │     old_values   │
                  │     new_values   │
                  │     ip_address   │
                  │     user_agent   │
                  │     status       │
                  │     error_message│
                  │     created_at   │
                  └──────────────────┘
```

## Table Definitions

### 1. roles
Stores role definitions for the RBAC system.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique role identifier |
| name | VARCHAR(50) | NOT NULL, UNIQUE | Role name (e.g., ADMIN, USER) |
| description | VARCHAR(255) | NULL | Role description |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | Whether role is active |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Indexes:**
- `idx_roles_name` on (name)

### 2. permissions
Stores granular permissions that can be assigned to roles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique permission identifier |
| name | VARCHAR(100) | NOT NULL, UNIQUE | Permission name (e.g., users.read) |
| resource | VARCHAR(50) | NOT NULL | Resource type (e.g., users, roles) |
| action | VARCHAR(50) | NOT NULL | Action type (e.g., read, create, update, delete) |
| description | VARCHAR(255) | NULL | Permission description |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |

**Indexes:**
- `idx_permissions_name` on (name)
- `idx_permissions_resource_action` on (resource, action)

### 3. users
Stores user account information and authentication data.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique user identifier |
| username | VARCHAR(50) | NOT NULL, UNIQUE | Username for login |
| email | VARCHAR(255) | NOT NULL, UNIQUE | Email address |
| password_hash | VARCHAR(255) | NOT NULL | Bcrypt password hash |
| first_name | VARCHAR(100) | NULL | User's first name |
| last_name | VARCHAR(100) | NULL | User's last name |
| phone | VARCHAR(20) | NULL | Phone number |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | Account active status |
| is_email_verified | BOOLEAN | NOT NULL, DEFAULT FALSE | Email verification status |
| email_verified_at | TIMESTAMP | NULL | Email verification timestamp |
| last_login_at | TIMESTAMP | NULL | Last successful login |
| password_changed_at | TIMESTAMP | NULL | Last password change |
| failed_login_attempts | INT | NOT NULL, DEFAULT 0 | Failed login counter |
| locked_until | TIMESTAMP | NULL | Account lock expiration |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Indexes:**
- `idx_users_username` on (username)
- `idx_users_email` on (email)
- `idx_users_is_active` on (is_active)

### 4. user_roles
Junction table linking users to their roles (many-to-many).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique identifier |
| user_id | BIGINT | NOT NULL, FK→users.id | Reference to user |
| role_id | BIGINT | NOT NULL, FK→roles.id | Reference to role |
| assigned_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Assignment timestamp |
| assigned_by | BIGINT | NULL | User who assigned the role |

**Constraints:**
- FK: user_id → users(id) ON DELETE CASCADE
- FK: role_id → roles(id) ON DELETE CASCADE
- UNIQUE: (user_id, role_id)

**Indexes:**
- `idx_user_roles_user_id` on (user_id)
- `idx_user_roles_role_id` on (role_id)

### 5. role_permissions
Junction table linking roles to permissions (many-to-many).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique identifier |
| role_id | BIGINT | NOT NULL, FK→roles.id | Reference to role |
| permission_id | BIGINT | NOT NULL, FK→permissions.id | Reference to permission |
| assigned_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Assignment timestamp |

**Constraints:**
- FK: role_id → roles(id) ON DELETE CASCADE
- FK: permission_id → permissions(id) ON DELETE CASCADE
- UNIQUE: (role_id, permission_id)

**Indexes:**
- `idx_role_permissions_role_id` on (role_id)
- `idx_role_permissions_permission_id` on (permission_id)

### 6. refresh_tokens
Stores JWT refresh tokens for authentication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique identifier |
| user_id | BIGINT | NOT NULL, FK→users.id | Token owner |
| token | VARCHAR(500) | NOT NULL, UNIQUE | Refresh token value |
| expires_at | TIMESTAMP | NOT NULL | Token expiration |
| is_revoked | BOOLEAN | NOT NULL, DEFAULT FALSE | Revocation status |
| revoked_at | TIMESTAMP | NULL | Revocation timestamp |
| ip_address | VARCHAR(45) | NULL | Client IP address (IPv4/IPv6) |
| user_agent | VARCHAR(500) | NULL | Client user agent |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |

**Constraints:**
- FK: user_id → users(id) ON DELETE CASCADE

**Indexes:**
- `idx_refresh_tokens_user_id` on (user_id)
- `idx_refresh_tokens_token` on (token)
- `idx_refresh_tokens_expires_at` on (expires_at)

### 7. audit_logs
Tracks user actions for security and compliance.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | BIGINT | PK, AUTO_INCREMENT | Unique identifier |
| user_id | BIGINT | NULL, FK→users.id | User who performed action |
| action | VARCHAR(100) | NOT NULL | Action performed |
| resource_type | VARCHAR(50) | NOT NULL | Type of resource affected |
| resource_id | BIGINT | NULL | ID of affected resource |
| old_values | TEXT | NULL | JSON of old values |
| new_values | TEXT | NULL | JSON of new values |
| ip_address | VARCHAR(45) | NULL | Client IP address |
| user_agent | VARCHAR(500) | NULL | Client user agent |
| status | VARCHAR(20) | NOT NULL | Action status (success/failure) |
| error_message | TEXT | NULL | Error details if failed |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Action timestamp |

**Constraints:**
- FK: user_id → users(id) ON DELETE SET NULL

**Indexes:**
- `idx_audit_logs_user_id` on (user_id)
- `idx_audit_logs_action` on (action)
- `idx_audit_logs_resource` on (resource_type, resource_id)
- `idx_audit_logs_created_at` on (created_at)

## Default Data

### Roles
1. **ADMIN** - Administrator with full system access
2. **USER** - Regular user with standard permissions
3. **MODERATOR** - Moderator with elevated user management
4. **GUEST** - Guest user with limited read-only access

### Permissions
- **users.read** - View user information
- **users.create** - Create new users
- **users.update** - Update user information
- **users.delete** - Delete users
- **roles.read** - View roles
- **roles.create** - Create roles
- **roles.update** - Update roles
- **roles.delete** - Delete roles
- **audit.read** - View audit logs
- **settings.manage** - Manage system settings

### Default Admin User
- Username: `admin`
- Password: `Admin@123`
- Email: `admin@example.com`
- Role: ADMIN

## Migration Strategy

All schema changes are managed through Liquibase changesets:

1. **001** - Create roles table
2. **002** - Create permissions table
3. **003** - Create users table
4. **004** - Create user_roles junction table
5. **005** - Create role_permissions junction table
6. **006** - Create refresh_tokens table
7. **007** - Create audit_logs table
8. **008** - Seed default data (roles, permissions, admin user)

## Security Considerations

1. **Password Storage**: All passwords are hashed using bcrypt with cost factor 10
2. **Account Locking**: Accounts lock after failed login attempts
3. **Token Management**: Refresh tokens can be revoked and have expiration times
4. **Audit Trail**: All significant actions are logged
5. **Soft Deletes**: Consider implementing soft deletes for users if needed
6. **Data Encryption**: Consider encrypting sensitive fields at application level

## Performance Optimization

1. All foreign keys are indexed
2. Frequently queried columns have dedicated indexes
3. Composite indexes for common query patterns
4. Consider partitioning audit_logs by date for large datasets

## Maintenance

### Cleanup Tasks
- Regularly purge expired refresh tokens
- Archive old audit logs
- Monitor and optimize slow queries
- Review and update indexes based on query patterns
