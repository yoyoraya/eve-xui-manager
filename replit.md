# X-UI Dashboard Monitor - Multi Server

## Overview
A professional web-based monitoring dashboard for multiple X-UI VPN panels with **enterprise security features**, secure authentication, and comprehensive statistics. Supports unlimited X-UI servers (Sanaei 3X-UI or Alireza X-UI).

## Security Features

### ✅ Implemented Security Measures

1. **Rate Limiting (Brute-Force Protection)**
   - **5 login attempts per minute** maximum per IP
   - Prevents automated password guessing attacks
   - Uses `Flask-Limiter` with in-memory storage
   - Global limits: 200 requests/day, 50 requests/hour per IP

2. **Secure Cookie Settings**
   - `SESSION_COOKIE_HTTPONLY=True`: Prevents JavaScript access to session cookies
   - `SESSION_COOKIE_SAMESITE='Lax'`: Protects against CSRF attacks (most situations)
   - Session cookies are secure and cannot be accessed from XSS attacks

3. **Environment-Based Default Password**
   - Initial admin password from `INITIAL_ADMIN_PASSWORD` environment variable
   - Falls back to `'admin'` if not set
   - Prevents hardcoded default credentials exposure
   - Can be changed via admin settings after login

4. **Failed Login Logging**
   - All failed login attempts are logged with username and IP address
   - Enables monitoring of suspicious activity
   - Useful for security audits and intrusion detection

5. **Password Hashing**
   - Uses Werkzeug's `generate_password_hash()` with PBKDF2 algorithm
   - Salted and hashed passwords stored in database
   - `check_password_hash()` for secure verification

### 🔒 Security Best Practices

- Session management with secure flags
- Disabled database modification tracking for performance
- Connection pooling with pre-ping health checks
- 7-day session lifetime (can be configured)

## Key Features

### Authentication & Security
- Professional login page with rate limiting
- Secure session management
- Admin management system (superadmin can manage other admins)
- Failed login attempt logging
- Environment variable support for sensitive configuration

### Multi-Server Support
- Add unlimited X-UI panels
- Auto-detect panel type (Sanaei 3X-UI vs Alireza X-UI)
- Per-server session handling
- **Customizable subscription and JSON paths** per server
- **Configurable subscription port** (handles different ports)

### Dashboard Features
- Sidebar navigation (responsive, mobile-friendly)
- Statistics overview: servers, inbounds, clients, traffic
- Inbound configurations with protocol, port, status
- **3-Column QR Code Grid** (Subscription, JSON, Direct Link)
- Traffic display and volume tracking
- Auto-refresh with configurable interval
- Manual refresh button

### Client Management
- Enable/Disable clients
- Reset client traffic
- Renew client with "Start after first use" option
- **3 Types of QR Codes per client:**
  - Subscription: Copy Sub
  - Subscription JSON: Copy JSON
  - Direct Link: Copy Direct (account connection link)

### Expiry Display
- Shows remaining days instead of dates
- "Start after first use" support
- Color-coded expiry badges
- Jalali calendar integration

### Responsive Design
- Mobile-friendly sidebar (hamburger menu)
- Responsive stats grid and tables
- Touch-friendly buttons
- 3-column QR grid → 2-column tablet → 1-column mobile

## Project Architecture

### Tech Stack
- **Backend**: Python 3.11 with Flask
- **Database**: PostgreSQL
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Security**: Werkzeug, Flask-Limiter
- **Styling**: Custom CSS dark theme

### File Structure
```
├── app.py                    # Main Flask application
├── templates/
│   ├── base.html            # Base template with sidebar
│   ├── login.html           # Login page
│   ├── dashboard.html       # Main dashboard
│   ├── servers.html         # Server management
│   └── admins.html          # Admin management
├── static/
│   └── style.css            # Comprehensive stylesheet
├── pyproject.toml           # Python dependencies
└── replit.md                # This file
```

## Database Schema

### Admins Table
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| username | String(100) | Unique username |
| password_hash | String(255) | Hashed password (PBKDF2) |
| is_superadmin | Boolean | Can manage other admins |
| enabled | Boolean | Account active status |
| created_at | DateTime | Creation timestamp |
| last_login | DateTime | Last login time |

### Servers Table
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| name | String(100) | Server display name |
| host | String(255) | X-UI panel URL |
| username | String(100) | Login username |
| password | String(255) | Login password |
| enabled | Boolean | Is server active |
| panel_type | String(50) | auto/sanaei/alireza |
| sub_path | String(50) | Subscription path (default: /sub/) |
| json_path | String(50) | JSON path (default: /json/) |
| sub_port | Integer | Optional subscription port |
| created_at | DateTime | Creation timestamp |

## API Endpoints

### Authentication
- `GET/POST /login` - Login page (rate limited: 5/min)
- `GET /logout` - Logout

### Pages
- `GET /` - Dashboard
- `GET /servers` - Server management
- `GET /admins` - Admin management

### API
- `GET /api/admins` - List admins
- `POST /api/admins` - Add admin
- `PUT /api/admins/<id>` - Update admin
- `DELETE /api/admins/<id>` - Delete admin
- `GET/POST/PUT/DELETE /api/servers` - Server CRUD
- `POST /api/servers/<id>/test` - Test connection
- `GET /api/refresh` - Refresh all data
- `POST /api/client/<server_id>/<inbound_id>/<email>/toggle` - Toggle client
- `POST /api/client/<server_id>/<inbound_id>/<email>/reset` - Reset traffic
- `POST /api/client/<server_id>/<inbound_id>/<email>/renew` - Renew client
- `GET /api/client/qrcode` - Generate QR code

## Environment Variables

### Required
- `DATABASE_URL` - PostgreSQL connection string

### Security
- `SESSION_SECRET` - Flask session secret key
- `INITIAL_ADMIN_PASSWORD` - Initial admin password (default: "admin")

### Optional
- `XUI_HOST`, `XUI_USERNAME`, `XUI_PASSWORD` - Default X-UI connection

## Default Credentials

- **Username**: `admin`
- **Password**: From `INITIAL_ADMIN_PASSWORD` env var (default: `admin`)
- ⚠️ **IMPORTANT**: Change password after first login!

## Recent Changes (December 2025)

- **December 01**: Security hardening
  - Added Flask-Limiter for rate limiting (5 attempts/minute)
  - Implemented secure cookie settings (HTTPONLY, SAMESITE)
  - Environment variable for initial admin password
  - Failed login attempt logging
  
- **December 01**: QR Code UI improvements
  - Fixed QR code sizing (140×140px) with responsive scaling
  - Prevent scroll overflow with optimized layout
  - 3 distinct labels: Copy Sub, Copy JSON, Copy Direct
  
- **December 01**: 3-Column QR Code Grid
  - Subscription QR code
  - Subscription JSON QR code
  - Direct connection link QR code
  
- **December 01**: Configurable subscription port
  - Added `sub_port` column to Server model
  - Per-server custom subscription port support
  - Updated subscription link generation
  
- **November 2025**: Full feature release
  - Multi-server support with unlimited panels
  - Professional login system
  - Admin management page
  - Responsive sidebar navigation
  - Panel type auto-detection
  - Client renewal with start-after-first-use
  - Expiry display as remaining days
  - Traffic and volume tracking
  - Mobile responsive design

## User Preferences
- Dark theme
- English-only interface (LTR)
- Clean, modern design
- Professional authentication
- Enterprise security

