# Quick Start Guide - Database Setup

## Step 1: Install Required Software

### PostgreSQL
1. Download installer: https://www.postgresql.org/download/windows/
2. Run installer with these settings:
   - Password for postgres user: `postgres123` (remember this!)
   - Port: `5432`
   - Locale: Default
3. Verify installation:
```powershell
psql --version
```

### SQL Server
1. Download SQL Server 2022 Developer Edition: https://www.microsoft.com/en-us/sql-server/sql-server-downloads
2. Click "Download now" for Developer edition
3. Run installer with:
   - Installation Type: Basic or Custom
   - Mixed Mode Authentication
   - SA Password: `YourStrong@Passw0rd`
4. Download SSMS: https://aka.ms/ssmsfullsetup
5. Verify installation: Open SSMS and connect to `localhost`

### Liquibase
1. Download: https://github.com/liquibase/liquibase/releases/latest
2. Extract ZIP to `C:\liquibase`
3. Add to system PATH:
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\liquibase", "User")
   ```
4. Restart PowerShell and verify:
   ```powershell
   liquibase --version
   ```

### JDBC Drivers
1. Create directory: `C:\liquibase\lib`
2. Download PostgreSQL driver:
   - Visit: https://jdbc.postgresql.org/download/
   - Download `postgresql-42.7.1.jar`
   - Place in `C:\liquibase\lib\`
3. Download SQL Server driver:
   - Visit: https://learn.microsoft.com/en-us/sql/connect/jdbc/download-microsoft-jdbc-driver-for-sql-server
   - Download "Microsoft JDBC Driver 12.4 for SQL Server"
   - Extract and copy `mssql-jdbc-12.4.2.jre11.jar` to `C:\liquibase\lib\`

## Step 2: Create Databases

### PostgreSQL
```powershell
# Open psql
psql -U postgres

# In psql, run these commands:
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'authpass123';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
\c authdb
GRANT ALL ON SCHEMA public TO authuser;
\q
```

### SQL Server
```powershell
# Open SSMS and connect to localhost
# Open a New Query window and run:
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

## Step 3: Run Liquibase Migrations

### PostgreSQL
```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps\migrations\postgresql
liquibase update
```

### SQL Server
```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps\migrations\mssql
liquibase update
```

## Step 4: Verify Setup

### PostgreSQL
```powershell
psql -U authuser -d authdb

# In psql:
\dt
SELECT * FROM roles;
SELECT * FROM users;
\q
```

### SQL Server
Open SSMS, connect to localhost, and run:
```sql
USE authdb;
GO

SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
SELECT * FROM roles;
SELECT * FROM users;
```

## Default Credentials

After setup, you'll have a default admin user:
- **Username**: `admin`
- **Password**: `Admin@123`
- **Email**: `admin@example.com`
- **Role**: ADMIN (full permissions)

## Database Schema

### Tables Created:
1. **roles** - User roles (ADMIN, USER, GUEST, MODERATOR)
2. **permissions** - Granular permissions (users.read, users.create, etc.)
3. **users** - User accounts with authentication
4. **user_roles** - Links users to roles
5. **role_permissions** - Links roles to permissions
6. **refresh_tokens** - JWT refresh token storage
7. **audit_logs** - Activity tracking

### Default Roles:
- **ADMIN**: Full system access
- **USER**: Standard user permissions
- **MODERATOR**: Elevated user management
- **GUEST**: Limited read-only access

### Default Permissions:
- `users.read`, `users.create`, `users.update`, `users.delete`
- `roles.read`, `roles.create`, `roles.update`, `roles.delete`
- `audit.read`
- `settings.manage`

## Troubleshooting

### PostgreSQL Not Starting
```powershell
# Check service status
Get-Service postgresql*

# Start service if stopped
Start-Service postgresql-x64-15
```

### SQL Server Not Starting
```powershell
# Check service status
Get-Service MSSQLSERVER

# Start service if stopped
Start-Service MSSQLSERVER
```

### Liquibase Connection Failed
- Verify database is running
- Check username/password in `liquibase.properties`
- Ensure JDBC drivers are in `C:\liquibase\lib`

### Permission Denied
- PostgreSQL: Check `pg_hba.conf` (usually in `C:\Program Files\PostgreSQL\15\data\`)
- SQL Server: Verify mixed mode authentication is enabled

## Next Steps

Once databases are set up:
1. Create Go application structure
2. Implement database connection layer
3. Build authentication handlers
4. Add authorization middleware
5. Create API endpoints

Check out `DATABASE_SETUP.md` for detailed information and connection strings.
