# TaskFlow - Task Management System

A production-ready Go backend service for task and project management with JWT authentication, RBAC authorization, and dual database support (PostgreSQL & SQL Server).

## 🎯 Project Overview

**TaskFlow** is a complete backend system that includes:
- **Foundation Layer**: Authentication, authorization (RBAC), user management, audit logging
- **Business Layer**: Task management, project management, collaboration features (to be implemented)

## 📁 Project Structure

```
go-task-manager-service/
├── migrations/                        # Database schema management
│   ├── postgresql/                    # PostgreSQL migrations
│   │   ├── liquibase.properties
│   │   ├── changelog-master.xml
│   │   └── changelogs/
│   │       ├── 001-create-roles-table.xml
│   │       ├── 002-create-permissions-table.xml
│   │       ├── 003-create-users-table.xml
│   │       ├── 004-create-user-roles-table.xml
│   │       ├── 005-create-role-permissions-table.xml
│   │       ├── 006-create-refresh-tokens-table.xml
│   │       ├── 007-create-audit-logs-table.xml
│   │       └── 008-seed-default-data.xml
│   └── mssql/                         # SQL Server migrations
│       ├── liquibase.properties
│       ├── changelog-master.xml
│       └── changelogs/
│           └── (same structure)
├── cmd/                               # Application entry points (to be created)
│   └── server/
│       └── main.go
├── internal/                          # Private application code (to be created)
│   ├── config/
│   ├── handlers/
│   ├── middleware/
│   ├── models/
│   ├── repository/
│   ├── services/
│   └── database/
├── pkg/                               # Public libraries (to be created)
│   ├── jwt/
│   └── utils/
├── docs/                              # API documentation (to be created)
├── README.md                          # This file
├── QUICK_START.md                     # Quick setup guide
├── DATABASE_SETUP.md                  # Database installation guide
├── DATABASE_SCHEMA.md                 # Schema documentation
└── IMPLEMENTATION_GUIDE.md            # Step-by-step implementation
```

## 🚀 Current Status

### ✅ Completed (Foundation)
- [x] Database schema design (7 tables)
- [x] Liquibase migration files for PostgreSQL
- [x] Liquibase migration files for SQL Server
- [x] User authentication schema
- [x] RBAC (roles & permissions) schema
- [x] Audit logging schema
- [x] Refresh token management schema
- [x] Default seed data (4 roles, 10 permissions, 1 admin user)
- [x] Complete documentation

### 🔨 To Be Implemented (Business Logic)
- [ ] Go application setup
- [ ] Database connection layer
- [ ] Authentication API (login, register, refresh)
- [ ] User management API
- [ ] **Projects module**
- [ ] **Tasks module**
- [ ] **Comments system**
- [ ] **File attachments**
- [ ] **Real-time updates (WebSockets)**
- [ ] **Notifications**
- [ ] **Search & filtering**
- [ ] **Dashboard & analytics**

## 📊 Database Schema

### Foundation Tables (Complete)
1. **users** - User accounts with authentication
2. **roles** - Role definitions (ADMIN, USER, MODERATOR, GUEST)
3. **permissions** - Granular permissions (users.read, users.create, etc.)
4. **user_roles** - Many-to-many: users ↔ roles
5. **role_permissions** - Many-to-many: roles ↔ permissions
6. **refresh_tokens** - JWT refresh token storage
7. **audit_logs** - Activity and security tracking

### Business Tables (To Be Added)
8. **projects** - Workspaces/projects
9. **tasks** - Work items/todos
10. **task_assignees** - Task assignments
11. **comments** - Task discussions
12. **attachments** - File uploads
13. **labels** - Tags for organization
14. **task_labels** - Task categorization
15. **notifications** - User alerts
16. **time_entries** - Time tracking (optional)

## 🗄️ Database Setup

### Database Names
- **PostgreSQL**: `taskflow_db`
- **SQL Server**: `taskflow_db`
- **Username**: `taskflow_user`
- **Password**: `taskflow_pass123`

### Quick Setup Commands

#### PostgreSQL
```sql
psql -U postgres
CREATE DATABASE taskflow_db;
CREATE USER taskflow_user WITH PASSWORD 'taskflow_pass123';
GRANT ALL PRIVILEGES ON DATABASE taskflow_db TO taskflow_user;
\c taskflow_db
GRANT ALL ON SCHEMA public TO taskflow_user;
\q
```

#### SQL Server
```sql
-- In SSMS
CREATE DATABASE taskflow_db;
GO
USE taskflow_db;
GO
CREATE LOGIN taskflow_user WITH PASSWORD = 'taskflow_pass123';
CREATE USER taskflow_user FOR LOGIN taskflow_user;
GRANT CONTROL ON DATABASE::taskflow_db TO taskflow_user;
GO
```

### Run Migrations

```powershell
# PostgreSQL
cd migrations\postgresql
liquibase update

# SQL Server
cd migrations\mssql
liquibase update
```

## 🔐 Default Credentials

After running migrations, you'll have a default admin account:
- **Username**: `admin`
- **Password**: `Admin@123`
- **Email**: `admin@example.com`
- **Role**: ADMIN (full permissions)

## 🛠️ Technology Stack

### Current (Foundation)
- **Schema Management**: Liquibase
- **Databases**: PostgreSQL 15+ and SQL Server 2022
- **Authentication**: JWT tokens with bcrypt password hashing

### Planned (Implementation)
- **Language**: Go 1.21+
- **Web Framework**: Chi router
- **Database Driver**: pgx (PostgreSQL), go-mssqldb (SQL Server)
- **JWT Library**: golang-jwt/jwt
- **Config**: Viper
- **Validation**: go-playground/validator
- **Logging**: zerolog
- **Testing**: testify

## 📚 Documentation

- **[QUICK_START.md](QUICK_START.md)** - Fast setup guide with step-by-step instructions
- **[DATABASE_SETUP.md](DATABASE_SETUP.md)** - Comprehensive database setup
- **[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)** - Complete schema with ER diagrams
- **[IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md)** - Implementation walkthrough

## 🎯 Learning Goals

This project is designed to teach all backend Go concepts:

1. **Basic CRUD** - Create, Read, Update, Delete operations
2. **REST API Design** - RESTful endpoints and best practices
3. **Authentication & Authorization** - JWT, RBAC, permissions
4. **Database Operations** - SQL queries, transactions, migrations
5. **File Handling** - Upload, download, storage management
6. **Real-time Features** - WebSockets, live updates
7. **Background Jobs** - Scheduled tasks, async processing
8. **Testing** - Unit tests, integration tests
9. **API Documentation** - OpenAPI/Swagger
10. **Production Ready** - Logging, monitoring, error handling

## 🗺️ Development Roadmap

### Phase 1: Foundation Setup (COMPLETED ✅)
- Database schema and migrations
- Documentation

### Phase 2: Go Application Setup (NEXT)
- Initialize Go module
- Create project structure
- Setup configuration management
- Database connection pooling

### Phase 3: Authentication & User Management
- JWT token generation/validation
- Login and register endpoints
- User CRUD operations
- Password reset flow

### Phase 4: Core Business Features
- Projects CRUD
- Tasks CRUD with status workflow
- Task assignment system
- Basic authorization

### Phase 5: Collaboration Features
- Comments system
- File attachments
- Activity feeds
- Notifications

### Phase 6: Advanced Features
- Real-time updates (WebSockets)
- Search and filtering
- Dashboard and analytics
- Time tracking

### Phase 7: Polish & Production
- Comprehensive testing
- API documentation
- Performance optimization
- Deployment guides

## 🧪 API Endpoints (Planned)

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user

### Users
- `GET /api/users` - List users (admin)
- `GET /api/users/:id` - Get user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user (admin)

### Projects
- `POST /api/projects` - Create project
- `GET /api/projects` - List user's projects
- `GET /api/projects/:id` - Get project
- `PUT /api/projects/:id` - Update project
- `DELETE /api/projects/:id` - Delete project

### Tasks
- `POST /api/projects/:id/tasks` - Create task
- `GET /api/projects/:id/tasks` - List project tasks
- `GET /api/tasks/:id` - Get task details
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task
- `POST /api/tasks/:id/assign` - Assign task
- `PUT /api/tasks/:id/status` - Update task status

### Comments
- `POST /api/tasks/:id/comments` - Add comment
- `GET /api/tasks/:id/comments` - List comments
- `PUT /api/comments/:id` - Update comment
- `DELETE /api/comments/:id` - Delete comment

### Attachments
- `POST /api/tasks/:id/attachments` - Upload file
- `GET /api/tasks/:id/attachments` - List files
- `GET /api/attachments/:id` - Download file
- `DELETE /api/attachments/:id` - Delete file

## 🤝 Contributing

This is a learning project. Feel free to:
- Fork and modify for your own learning
- Submit issues if you find problems
- Share improvements and suggestions

## 📄 License

This is an educational project - use it however you like!

## 🎓 Next Steps

1. **Follow QUICK_START.md** to set up your databases
2. **Run migrations** to create the schema
3. **Verify setup** with test queries
4. **Start implementing** the Go application (Phase 2)

---

**Project**: TaskFlow Task Management System  
**Status**: Foundation Complete ✅ | Implementation In Progress 🚧  
**Database**: Ready ✅  
**Go Application**: Not Started ⏳
