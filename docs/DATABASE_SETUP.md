# Database Setup Guide - Local Installation

## Prerequisites

### 1. PostgreSQL (Windows)
- Download: https://www.postgresql.org/download/windows/
- Version: 15.x or higher
- During installation:
  - Set password for `postgres` superuser (remember this!)
  - Port: 5432 (default)
  - Locale: Default

### 2. SQL Server (Windows)
- Download SQL Server 2022 Developer Edition (free): https://www.microsoft.com/en-us/sql-server/sql-server-downloads
- Or SQL Server Express (free)
- Download SSMS: https://aka.ms/ssmsfullsetup
- During installation:
  - Mixed Mode Authentication
  - Set SA password: `YourStrong@Passw0rd`
  - Port: 1433 (default)

### 3. Liquibase
- Download: https://github.com/liquibase/liquibase/releases
- Extract to `C:\liquibase`
- Add to PATH: `C:\liquibase`
- Verify: `liquibase --version`

### 4. JDBC Drivers
Download these drivers and place in `C:\liquibase\lib`:
- PostgreSQL: https://jdbc.postgresql.org/download/
  - File: `postgresql-42.7.1.jar`
- SQL Server: https://learn.microsoft.com/en-us/sql/connect/jdbc/download-microsoft-jdbc-driver-for-sql-server
  - File: `mssql-jdbc-12.4.2.jre11.jar`

## Database Creation

### PostgreSQL
```powershell
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'authpass123';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\c authdb
GRANT ALL ON SCHEMA public TO authuser;
\q
```

### SQL Server
```powershell
# Open SQL Server Management Studio (SSMS)
# Connect to localhost with Windows Authentication or SA account
# Run these queries:
```

```sql
-- Create database
CREATE DATABASE authdb;
GO

-- Create login and user
USE authdb;
GO

CREATE LOGIN authuser WITH PASSWORD = 'authpass123';
CREATE USER authuser FOR LOGIN authuser;
GRANT CONTROL ON DATABASE::authdb TO authuser;
GO
```

## Schema Overview

The authentication system includes these tables:

1. **users** - User accounts with credentials
2. **roles** - Role definitions (Admin, User, Guest)
3. **permissions** - Granular permissions
4. **user_roles** - Link users to roles (many-to-many)
5. **role_permissions** - Link roles to permissions (many-to-many)
6. **refresh_tokens** - JWT refresh token storage
7. **audit_logs** - User activity tracking

## Running Liquibase Migrations

### PostgreSQL
```powershell
cd migrations/postgresql
liquibase --changelog-file=changelog-master.xml update
```

### SQL Server
```powershell
cd migrations/mssql
liquibase --changelog-file=changelog-master.xml update
```

## Connection Strings

### PostgreSQL
```
Host: localhost
Port: 5432
Database: authdb
Username: authuser
Password: authpass123
Connection String: postgresql://authuser:authpass123@localhost:5432/authdb?sslmode=disable
```

### SQL Server
```
Host: localhost
Port: 1433
Database: authdb
Username: authuser
Password: authpass123
Connection String: sqlserver://authuser:authpass123@localhost:1433?database=authdb
```

## Verification

### PostgreSQL
```powershell
psql -U authuser -d authdb -c "\dt"
```

### SQL Server
```sql
USE authdb;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

## Troubleshooting

### PostgreSQL Connection Issues
- Verify service is running: `services.msc` → postgresql-x64-15
- Check `pg_hba.conf` for authentication settings
- Default location: `C:\Program Files\PostgreSQL\15\data\pg_hba.conf`

### SQL Server Connection Issues
- Verify service is running: `services.msc` → SQL Server (MSSQLSERVER)
- Enable TCP/IP: SQL Server Configuration Manager → SQL Server Network Configuration
- Restart SQL Server service after changes

## Next Steps

After database setup:
1. Run Liquibase migrations
2. Verify all tables are created
3. Initialize default roles and permissions
4. Start developing the Go application
