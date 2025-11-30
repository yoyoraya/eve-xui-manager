# X-UI Dashboard Monitor - Multi Server

## Overview
A professional web-based monitoring dashboard for multiple X-UI VPN panels with secure authentication. This application connects to unlimited X-UI servers (Sanaei 3X-UI or Alireza X-UI) and displays comprehensive statistics with client management capabilities.

## Key Features

### Authentication & Security
- Professional login page with secure session management
- Password hashing with Werkzeug security
- Admin management system (superadmin can manage other admins)
- Session-based authentication with login_required decorator

### Multi-Server Support
- Add unlimited X-UI panels
- Auto-detect panel type (Sanaei 3X-UI vs Alireza X-UI)
- Per-server session handling and cookie management
- Server CRUD operations (add, edit, delete, test connection)

### Dashboard Features
- Sidebar navigation menu (responsive)
- Statistics overview: servers, inbounds, clients, traffic
- Inbound configurations with protocol, port, and status
- Traffic display: upload/download in single column
- Remaining and total volume display

### Client Management
- Enable/Disable clients
- Reset client traffic
- Renew client with dialog box:
  - Set days and volume
  - "Start after first use" toggle option
- QR Code generation
- Subscription link copying

### Expiry Display
- Shows "remaining days" instead of dates
- Handles "Start after first use" feature
- Color-coded expiry badges (expired, soon, normal)

### Responsive Design
- Mobile-friendly sidebar (hamburger menu)
- Responsive stats grid
- Touch-friendly action buttons
- Horizontal scrolling for tables on mobile

## Project Architecture

### Tech Stack
- **Backend**: Python 3.11 with Flask
- **Database**: PostgreSQL (with SQLite fallback)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Custom CSS with modern dark theme, RTL support
- **Authentication**: Werkzeug password hashing

### File Structure
```
├── app.py                    # Main Flask application
├── templates/
│   ├── base.html            # Base template with sidebar
│   ├── login.html           # Login page
│   ├── dashboard.html       # Main dashboard
│   └── admins.html          # Admin management page
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
| password_hash | String(255) | Hashed password |
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
| created_at | DateTime | Creation timestamp |

## API Endpoints

### Authentication
- `GET/POST /login` - Login page
- `GET /logout` - Logout and clear session

### Frontend Pages
- `GET /` - Main dashboard (requires login)
- `GET /admins` - Admin management (superadmin only)

### Admin Management API
- `GET /api/admins` - List all admins
- `POST /api/admins` - Add new admin
- `PUT /api/admins/<id>` - Update admin
- `DELETE /api/admins/<id>` - Delete admin

### Server Management API
- `GET /api/servers` - List all servers
- `POST /api/servers` - Add new server
- `PUT /api/servers/<id>` - Update server
- `DELETE /api/servers/<id>` - Delete server
- `POST /api/servers/<id>/test` - Test connection & detect panel type

### Data API
- `GET /api/refresh` - Get updated data from all servers

### Client Actions API
- `POST /api/client/<server_id>/<inbound_id>/<email>/toggle` - Enable/disable
- `POST /api/client/<server_id>/<inbound_id>/<email>/reset` - Reset traffic
- `POST /api/client/<server_id>/<inbound_id>/<email>/renew` - Renew client
- `GET /api/client/qrcode?link=<link>` - Generate QR code

## Panel Type Detection

### Sanaei 3X-UI
- API Base: `/panel/api/`
- Endpoints: `/panel/api/inbounds/list`, `/panel/api/inbounds/onlines`
- Documentation: https://documenter.getpostman.com/view/5146551/2sB3QCTuB6

### Alireza X-UI
- API Base: `/xui/`
- Endpoints: `/xui/inbound/list`, `/xui/API/inbounds`
- Documentation: https://github.com/alireza0/x-ui

## Default Credentials
- Username: `admin`
- Password: `admin`
- **Important**: Change these after first login!

## Recent Changes
- November 2025: Added professional login system
- November 2025: Implemented admin management page
- November 2025: Added sidebar navigation
- November 2025: Panel type auto-detection
- November 2025: Client renewal dialog with start-after-first-use
- November 2025: Expiry displayed as remaining days
- November 2025: Traffic display improved (upload/download combined)
- November 2025: Mobile responsive design

## User Preferences
- Dark theme preferred
- Persian/Farsi UI support (RTL)
- Clean, modern design
- Multi-server architecture
- Professional authentication
