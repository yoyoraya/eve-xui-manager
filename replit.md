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

## Panel Type Detection & X-UI API Routes

### Sanaei 3X-UI

#### Authentication
- `POST /login` - Login with `{username: '', password: ''}`

#### Inbounds API
Base path: `/panel/api/inbounds`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list` | Get all inbounds |
| GET | `/get/:id` | Get inbound by ID |
| GET | `/getClientTraffics/:email` | Get client traffics by email |
| GET | `/getClientTrafficsById/:id` | Get client traffics by inbound ID |
| POST | `/add` | Add new inbound |
| POST | `/del/:id` | Delete inbound by ID |
| POST | `/update/:id` | Update inbound by ID |
| POST | `/clientIps/:email` | Get client IP addresses |
| POST | `/clearClientIps/:email` | Clear client IP addresses |
| POST | `/addClient` | Add client to inbound |
| POST | `/:id/delClient/:clientId` | Delete client by clientId* |
| POST | `/updateClient/:clientId` | Update client by clientId* |
| POST | `/:id/resetClientTraffic/:email` | Reset a client's traffic usage |
| POST | `/resetAllTraffics` | Reset traffics for all inbounds |
| POST | `/resetAllClientTraffics/:id` | Reset traffics for all clients in inbound |
| POST | `/delDepletedClients/:id` | Delete depleted clients in inbound (-1: all) |
| POST | `/import` | Import inbound configuration |
| POST | `/onlines` | Get currently online clients (emails list) |
| POST | `/lastOnline` | Get last online status of clients |
| POST | `/updateClientTraffic/:email` | Update traffic for specific client |
| POST | `/{id}/delClientByEmail/{email}` | Delete client by email |

*clientId mapping:
- `client.id` for VMESS/VLESS
- `client.password` for TROJAN
- `client.email` for Shadowsocks

#### Server API
Base path: `/panel/api/server`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | Get server status |
| GET | `/getXrayVersion` | Get available Xray versions |
| GET | `/getConfigJson` | Download current config.json |
| GET | `/getDb` | Download database file (x-ui.db) |
| GET | `/getNewUUID` | Generate new UUID |
| GET | `/getNewX25519Cert` | Generate new X25519 certificate |
| GET | `/getNewmldsa65` | Generate new ML-DSA-65 certificate |
| GET | `/getNewmlkem768` | Generate new ML-KEM-768 key pair |
| GET | `/getNewVlessEnc` | Generate new VLESS encryption keys |
| POST | `/stopXrayService` | Stop Xray service |
| POST | `/restartXrayService` | Restart Xray service |
| POST | `/installXray/:version` | Install/Update Xray to given version |
| POST | `/updateGeofile` | Update GeoIP/GeoSite data files |
| POST | `/updateGeofile/:fileName` | Update specific Geo file |
| POST | `/logs/:count` | Get system logs (with level, syslog) |
| POST | `/xraylogs/:count` | Get Xray logs (with filters) |
| POST | `/importDB` | Import database |
| POST | `/getNewEchCert` | Generate new ECH certificate (requires sni) |

#### Extra API
Base path: `/panel/api`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/backuptotgbot` | Backup DB/config and send to Telegram Bot |

Documentation: https://documenter.getpostman.com/view/5146551/2sB3QCTuB6

### Alireza X-UI (علیرضا)
- API Base: `/xui/API/`

#### Authentication
- `POST /login` - Login with `{username: '', password: ''}`

#### Inbounds API
Base path: `/xui/API/inbounds`

| Method | Path | Action |
|--------|------|--------|
| GET | `/` | Get all inbounds |
| GET | `/get/:id` | Get inbound by ID |
| POST | `/add` | Add new inbound |
| POST | `/del/:id` | Delete inbound by ID |
| POST | `/update/:id` | Update inbound by ID |
| POST | `/addClient/` | Add client to inbound |
| POST | `/:id/delClient/:clientId` | Delete client by clientId* |
| POST | `/updateClient/:clientId` | Update client by clientId* |
| GET | `/getClientTraffics/:email` | Get client traffic by email |
| GET | `/getClientTrafficsById/:id` | Get client traffic by ID |
| POST | `/:id/resetClientTraffic/:email` | Reset client traffic |
| POST | `/resetAllTraffics` | Reset all traffics |
| POST | `/resetAllClientTraffics/:id` | Reset all client traffics in inbound |
| POST | `/delDepletedClients/:id` | Delete depleted clients (-1: all) |
| POST | `/onlines` | Get online users (list of emails) |

*clientId mapping:
- `client.id` for VMess/VLESS
- `client.password` for Trojan
- `client.email` for Shadowsocks

#### Server API
Base path: `/xui/API/server`

| Method | Path | Action |
|--------|------|--------|
| GET | `/status` | Get server status |
| GET | `/getXrayVersion` | Get available Xray versions |
| GET | `/getConfigJson` | Download config.json |
| GET | `/getDb` | Download database file |
| GET | `/getNewUUID` | Generate new UUID |
| GET | `/getNewX25519Cert` | Generate X25519 certificate |
| GET | `/getNewmldsa65` | Generate ML-DSA-65 certificate |
| GET | `/getNewVlessEnc` | Generate VLESS encryption keys |
| POST | `/stopXrayService` | Stop Xray service |
| POST | `/restartXrayService` | Restart Xray service |
| POST | `/installXray/:version` | Install/Update Xray version |
| POST | `/logs/:count` | Get system logs |
| POST | `/xraylogs/:count` | Get Xray logs |
| POST | `/importDB` | Import database |

Documentation: https://github.com/alireza0/x-ui

## "Start After First Use" Feature

When a client has a **negative expiryTime**, it means the expiry date should be set **after the first connection**. This is used for clients where the subscription timer should start only when they first connect.

### Renewal Logic with "Start After First Use"

When renewing a client with this feature enabled:

**Formula**: `expiryTime = -1 * (days * 86400000)`
- `86400000` = milliseconds per day
- Example: 30 days = `-30 * 86400000 = -2592000000`

**In the panel (Web UI)**: Shows as "30 Days (Not Started)" or similar

**After first connection**: The panel detects the negative value and converts it to a proper expiry timestamp (current time + |negative value|)

### Implementation Details

1. **Set negative timestamp**: Send `expiryTime = -(days * 86400000)` to X-UI API
2. **Reset traffic automatically**: After renewal, call `resetClientTraffic` endpoint to prevent disconnection due to old quota
3. **Enable client**: Ensure `enable: true` is set
4. **Set reset flag**: Keep `reset: 0` (not used for this feature)

### Detection in Dashboard

The feature is detected by checking:
- `expiryTime < 0` (negative timestamp)
- `expiryTimeStr == 'StartAfterFirstUse'`
- `expiryOption == 'after_first_use'`

When detected, the UI shows: "Start after first use" with a special badge color

## Default Credentials
- Username: `admin`
- Password: `admin`
- **Important**: Change these after first login!

## Recent Changes
- November 2025: Removed bilingual support - English-only interface
- November 2025: Compact inbound display (network, security, clients, traffic on one line)
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
- English-only interface (LTR)
- Clean, modern design
- Multi-server architecture
- Professional authentication
