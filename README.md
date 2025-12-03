# TaskFlow - Task Management System

A production-ready Go backend service for task and project management with JWT authentication, RBAC authorization, and dual database support.

## 🎯 What is TaskFlow?

TaskFlow is a complete backend system that includes:
- **Foundation**: Authentication, authorization (RBAC), user management, audit logging
- **Business Logic**: Task management, project management, collaboration features

## 📊 Current Status

- ✅ **Phase 1 Complete**: Database schema and migrations ready
- 🚧 **Phase 2 Next**: Go application implementation
- ⏳ **Phase 3+**: API endpoints and business features

## 🚀 Quick Start

### 1. Prerequisites
- PostgreSQL 15+
- SQL Server 2022
- Liquibase
- Go 1.21+

### 2. Database Setup

```bash
# Create databases
psql -U postgres -c "CREATE DATABASE taskflow_db;"
psql -U postgres -c "CREATE USER taskflow_user WITH PASSWORD 'taskflow_pass123';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE taskflow_db TO taskflow_user;"

# Run migrations
cd migrations/postgresql
liquibase update
```

### 3. Verify Setup

```bash
psql -U taskflow_user -d taskflow_db -c "\dt"
```

You should see 7 tables: users, roles, permissions, user_roles, role_permissions, refresh_tokens, audit_logs

## 📁 Project Structure

```
go-task-manager-service/
├── docs/                      # 📚 All documentation
│   ├── PROJECT_README.md      # Complete project overview
│   ├── QUICK_START.md         # Fast setup guide
│   ├── DATABASE_SETUP.md      # Database installation
│   ├── DATABASE_SCHEMA.md     # Schema documentation
│   ├── IMPLEMENTATION_GUIDE.md # Step-by-step guide
│   └── PROJECT_STATUS.md      # Current status
├── migrations/                # Database migrations
│   ├── postgresql/
│   └── mssql/
├── cmd/                       # (To be created) Application entry
├── internal/                  # (To be created) Private code
├── pkg/                       # (To be created) Public libraries
└── README.md                  # This file
```

## 📚 Documentation

All detailed documentation is in the **`docs/`** folder:

| Document | Purpose |
|----------|---------|
| **[PROJECT_README.md](docs/PROJECT_README.md)** | Complete project overview and roadmap |
| **[PROJECT_STATUS.md](docs/PROJECT_STATUS.md)** | Current status and next steps |
| **[QUICK_START.md](docs/QUICK_START.md)** | Fast-track setup guide |
| **[DATABASE_SETUP.md](docs/DATABASE_SETUP.md)** | Detailed database installation |
| **[DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md)** | Complete schema with ER diagrams |
| **[IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md)** | Step-by-step implementation |

## 🗄️ Database

- **Name**: `taskflow_db` (PostgreSQL and SQL Server)
- **User**: `taskflow_user`
- **Password**: `taskflow_pass123`

### Default Admin Account
- Username: `admin`
- Password: `Admin@123`
- Email: `admin@example.com`

## 🛠️ Technology Stack

**Current:**
- Liquibase for schema management
- PostgreSQL 15+ and SQL Server 2022

**Planned:**
- Go 1.21+
- Chi router
- JWT authentication
- Viper for config
- Zerolog for logging

## 🗺️ Roadmap

- [x] **Phase 1**: Database schema and migrations
- [ ] **Phase 2**: Go application setup
- [ ] **Phase 3**: Authentication API
- [ ] **Phase 4**: Core business features (Projects, Tasks)
- [ ] **Phase 5**: Collaboration (Comments, Files)
- [ ] **Phase 6**: Advanced features (WebSockets, Search)
- [ ] **Phase 7**: Production polish

## 📖 Getting Started

1. **Read the docs**: Start with [PROJECT_README.md](docs/PROJECT_README.md)
2. **Setup databases**: Follow [QUICK_START.md](docs/QUICK_START.md)
3. **Run migrations**: Execute Liquibase migrations
4. **Verify**: Check that all tables are created
5. **Start coding**: Begin Phase 2 implementation

## 🎓 Learning Objectives

This project teaches:
- Go backend development
- RESTful API design
- JWT authentication
- RBAC authorization
- Database operations
- File handling
- Real-time features (WebSockets)
- Background jobs
- Testing and documentation
- Production deployment

## 📄 License

Educational project - use it however you like!

---

**For detailed documentation, see the [`docs/`](docs/) folder.**
