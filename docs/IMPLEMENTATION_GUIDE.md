# Implementation Guide

This guide walks you through implementing the database setup and understanding the complete system.

## 📋 What You Have Now

I've created a complete database schema with Liquibase migrations for your authentication and authorization system:

### ✅ Files Created
```
C:\Users\HashanEranga\Documents\projects\goApps\
├── README.md                          # Project overview
├── QUICK_START.md                     # Fast setup guide
├── DATABASE_SETUP.md                  # Detailed database instructions
├── DATABASE_SCHEMA.md                 # Complete schema documentation
├── IMPLEMENTATION_GUIDE.md            # This file
└── migrations/
    ├── postgresql/
    │   ├── liquibase.properties       # PostgreSQL connection config
    │   ├── changelog-master.xml       # Master changelog
    │   └── changelogs/
    │       ├── 001-create-roles-table.xml
    │       ├── 002-create-permissions-table.xml
    │       ├── 003-create-users-table.xml
    │       ├── 004-create-user-roles-table.xml
    │       ├── 005-create-role-permissions-table.xml
    │       ├── 006-create-refresh-tokens-table.xml
    │       ├── 007-create-audit-logs-table.xml
    │       └── 008-seed-default-data.xml
    └── mssql/
        ├── liquibase.properties       # SQL Server connection config
        ├── changelog-master.xml       # Master changelog
        └── changelogs/
            └── (same structure as PostgreSQL)
```

## 🎯 Your Implementation Path

### Phase 1: Database Setup (START HERE)

#### Step 1.1: Install PostgreSQL
1. Download from: https://www.postgresql.org/download/windows/
2. Run installer
3. Set postgres password (e.g., `postgres123`)
4. Keep default port: 5432
5. Verify: Open command prompt and run `psql --version`

#### Step 1.2: Install SQL Server
1. Download SQL Server 2022 Developer Edition
2. Choose "Basic" installation
3. Set SA password: `YourStrong@Passw0rd`
4. Keep default port: 1433
5. Download SSMS: https://aka.ms/ssmsfullsetup
6. Verify: Open SSMS and connect to `localhost`

#### Step 1.3: Install Liquibase
1. Download: https://github.com/liquibase/liquibase/releases
2. Extract to `C:\liquibase`
3. Add to system PATH:
   - Windows Key + Search "Environment Variables"
   - Click "Environment Variables"
   - Under "System variables", find "Path"
   - Click "Edit" → "New"
   - Add: `C:\liquibase`
   - Click OK on all dialogs
4. **Restart PowerShell**
5. Verify: `liquibase --version`

#### Step 1.4: Download JDBC Drivers
1. Create folder: `C:\liquibase\lib`
2. PostgreSQL driver:
   - Visit: https://jdbc.postgresql.org/download/
   - Download `postgresql-42.7.1.jar`
   - Save to `C:\liquibase\lib\`
3. SQL Server driver:
   - Visit: https://learn.microsoft.com/en-us/sql/connect/jdbc/download-microsoft-jdbc-driver-for-sql-server
   - Download "Microsoft JDBC Driver 12.4 for SQL Server"
   - Extract the zip
   - Copy `mssql-jdbc-12.4.2.jre11.jar` to `C:\liquibase\lib\`

#### Step 1.5: Create Databases

**For PostgreSQL:**
```powershell
# Open PowerShell and run:
psql -U postgres

# In psql prompt, run these commands one by one:
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'authpass123';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\c authdb
GRANT ALL ON SCHEMA public TO authuser;
\q
```

**For SQL Server:**
```powershell
# Open SQL Server Management Studio (SSMS)
# Connect to: localhost (use Windows Authentication or SA account)
# Click "New Query" and run:
```
```sql
CREATE DATABASE authdb;
GO

USE authdb;
GO

CREATE LOGIN authuser WITH PASSWORD = 'authpass123';
CREATE USER authuser FOR LOGIN authuser;
GRANT CONTROL ON DATABASE::authdb TO authuser;
GO
```

#### Step 1.6: Run Liquibase Migrations

**For PostgreSQL:**
```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps\migrations\postgresql
liquibase update
```

Expected output:
```
Liquibase Community 4.x.x by Liquibase
Running Changeset: changelogs/001-create-roles-table.xml::001-create-roles-table::system
Running Changeset: changelogs/002-create-permissions-table.xml::002-create-permissions-table::system
...
Liquibase command 'update' was executed successfully.
```

**For SQL Server:**
```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps\migrations\mssql
liquibase update
```

#### Step 1.7: Verify Database Setup

**PostgreSQL verification:**
```powershell
psql -U authuser -d authdb

# Run these in psql:
\dt                          # List all tables
SELECT * FROM roles;         # Should show 4 roles
SELECT * FROM users;         # Should show 1 admin user
SELECT * FROM permissions;   # Should show 10 permissions
\q
```

**SQL Server verification:**
```sql
-- In SSMS, run:
USE authdb;
GO

SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_TYPE = 'BASE TABLE' 
ORDER BY TABLE_NAME;

SELECT * FROM roles;
SELECT * FROM users;
SELECT * FROM permissions;
```

You should see:
- **7 tables**: audit_logs, permissions, refresh_tokens, role_permissions, roles, user_roles, users
- **4 roles**: ADMIN, USER, MODERATOR, GUEST
- **1 user**: admin (email: admin@example.com)
- **10 permissions**: users.read, users.create, etc.

### Phase 2: Understanding the Schema

#### Database Tables Explained

1. **users** - Stores user accounts
   - Unique username and email
   - Password stored as bcrypt hash
   - Account locking support (failed_login_attempts, locked_until)
   - Email verification tracking

2. **roles** - Defines user roles
   - ADMIN: Full access
   - USER: Standard permissions
   - MODERATOR: User management
   - GUEST: Read-only

3. **permissions** - Granular permissions
   - Format: `resource.action` (e.g., users.read, users.create)
   - Assigned to roles, not directly to users

4. **user_roles** - Links users to roles
   - A user can have multiple roles
   - Tracks who assigned the role

5. **role_permissions** - Links roles to permissions
   - Defines what each role can do

6. **refresh_tokens** - JWT refresh token storage
   - For token rotation and revocation
   - Tracks device info (IP, user agent)

7. **audit_logs** - Activity tracking
   - Who did what, when
   - Stores old and new values for changes

#### How RBAC Works

```
User Login
    ↓
Check user_roles to get user's roles
    ↓
Check role_permissions to get permissions for those roles
    ↓
Validate if user has required permission
    ↓
Allow/Deny access
```

Example:
- User "john" has role "USER"
- Role "USER" has permissions: users.read, users.update
- John can read and update users, but NOT delete them

### Phase 3: Test the Setup

#### Test with Sample Queries

**PostgreSQL:**
```sql
-- Connect
psql -U authuser -d authdb

-- Get all admin permissions
SELECT p.name 
FROM permissions p
JOIN role_permissions rp ON p.id = rp.permission_id
JOIN roles r ON rp.role_id = r.id
WHERE r.name = 'ADMIN';

-- Get admin user's roles
SELECT r.name 
FROM roles r
JOIN user_roles ur ON r.id = ur.role_id
JOIN users u ON ur.user_id = u.id
WHERE u.username = 'admin';

-- Insert a test user
INSERT INTO users (username, email, password_hash, first_name, last_name, is_active)
VALUES ('testuser', 'test@example.com', '$2a$10$dummy', 'Test', 'User', true);

-- Assign USER role to test user
INSERT INTO user_roles (user_id, role_id)
VALUES (
    (SELECT id FROM users WHERE username = 'testuser'),
    (SELECT id FROM roles WHERE name = 'USER')
);
```

### Phase 4: Next Steps for Go Development

Once your database is set up and verified, you'll create the Go application:

#### 1. Initialize Go Project
```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps
mkdir go-auth-server
cd go-auth-server
go mod init github.com/yourusername/go-auth-server
```

#### 2. Project Structure to Create
```
go-auth-server/
├── cmd/
│   └── server/
│       └── main.go                 # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go              # Configuration management
│   ├── database/
│   │   ├── postgres.go            # PostgreSQL connection
│   │   └── mssql.go               # SQL Server connection
│   ├── models/
│   │   ├── user.go                # User model
│   │   ├── role.go                # Role model
│   │   └── permission.go          # Permission model
│   ├── repository/
│   │   ├── user_repository.go     # User data access
│   │   └── auth_repository.go     # Auth data access
│   ├── services/
│   │   ├── auth_service.go        # Authentication logic
│   │   └── user_service.go        # User management logic
│   ├── handlers/
│   │   ├── auth_handler.go        # Login/Register endpoints
│   │   └── user_handler.go        # User CRUD endpoints
│   └── middleware/
│       ├── auth_middleware.go     # JWT validation
│       └── rbac_middleware.go     # Permission checking
├── pkg/
│   ├── jwt/
│   │   └── jwt.go                 # JWT utilities
│   └── response/
│       └── response.go            # HTTP response helpers
├── .env                            # Environment variables
└── go.mod                          # Go dependencies
```

#### 3. Key Go Packages to Use
```go
// Database
"database/sql"
"github.com/lib/pq"                    // PostgreSQL
"github.com/microsoft/go-mssqldb"      // SQL Server

// Web framework
"github.com/go-chi/chi/v5"

// JWT
"github.com/golang-jwt/jwt/v5"

// Password hashing
"golang.org/x/crypto/bcrypt"

// Configuration
"github.com/spf13/viper"

// Validation
"github.com/go-playground/validator/v10"
```

## 🎓 Learning Resources

### Understanding the Components

1. **Liquibase Migrations**
   - Each changeset is a database change
   - Changesets are applied in order
   - Liquibase tracks which changes are applied
   - You can rollback changes if needed

2. **RBAC (Role-Based Access Control)**
   - Users have roles
   - Roles have permissions
   - Check permissions, not roles, in your code
   - Example: Check if user has "users.delete", not "is admin"

3. **JWT Authentication**
   - Access token: Short-lived (15 minutes)
   - Refresh token: Long-lived (7 days), stored in database
   - Access token validates requests
   - Refresh token gets new access token

## 🔍 Troubleshooting Common Issues

### Issue: Liquibase not found
**Solution:**
```powershell
# Verify PATH
$env:Path -split ';' | Select-String liquibase

# If not found, add to PATH and restart PowerShell
```

### Issue: Connection refused
**Solution:**
```powershell
# Check if database is running
Get-Service postgresql*    # PostgreSQL
Get-Service MSSQLSERVER    # SQL Server

# Start if stopped
Start-Service postgresql-x64-15
Start-Service MSSQLSERVER
```

### Issue: Permission denied
**Solution:**
- PostgreSQL: Check if user has privileges: `GRANT ALL ON SCHEMA public TO authuser;`
- SQL Server: Check if user has CONTROL permission

### Issue: Liquibase can't find driver
**Solution:**
Verify JDBC jar files are in `C:\liquibase\lib\`:
```powershell
dir C:\liquibase\lib
```

## 📞 What to Do If Stuck

1. **Check the documentation files:**
   - `README.md` - Overview
   - `QUICK_START.md` - Step-by-step setup
   - `DATABASE_SCHEMA.md` - Schema details

2. **Verify each step:**
   - Is PostgreSQL/SQL Server running?
   - Can you connect with psql/SSMS?
   - Are JDBC drivers in the right place?
   - Did Liquibase migrations complete successfully?

3. **Test the database:**
   - Can you query the tables?
   - Does the default admin user exist?
   - Are all 7 tables created?

## ✅ Checklist

- [ ] PostgreSQL installed and running
- [ ] SQL Server installed and running
- [ ] SSMS installed
- [ ] Liquibase installed and in PATH
- [ ] JDBC drivers downloaded to C:\liquibase\lib
- [ ] authdb database created in PostgreSQL
- [ ] authdb database created in SQL Server
- [ ] authuser created in both databases
- [ ] Liquibase migrations run successfully for PostgreSQL
- [ ] Liquibase migrations run successfully for SQL Server
- [ ] Can connect to both databases
- [ ] Can query roles table (should have 4 roles)
- [ ] Can query users table (should have 1 admin user)
- [ ] Default admin user can be found: username=admin, email=admin@example.com

## 🎉 Success Criteria

You'll know everything is working when:
1. Both databases have all 7 tables
2. You can log in to both databases
3. You can run SELECT queries successfully
4. The admin user exists with ADMIN role
5. All 4 roles and 10 permissions are created

---

**Current Status**: Database schema complete ✅
**Next Phase**: Begin Go application development
**Est. Time to Complete Setup**: 1-2 hours (if installing everything from scratch)
