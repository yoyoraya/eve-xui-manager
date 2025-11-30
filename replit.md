# X-UI Dashboard Monitor - Multi Server

## Overview
A web-based monitoring dashboard for multiple X-UI VPN panels. This application connects to unlimited X-UI servers and displays:
- Inbound configurations with protocol, port, and status
- Traffic statistics (upload/download) in human-readable format
- Client information under each inbound with action buttons
- Configurable auto-refresh functionality
- QR Code and subscription link generation

## Project Architecture

### Tech Stack
- **Backend**: Python 3.11 with Flask
- **Database**: PostgreSQL (for storing server configurations)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Custom CSS with modern dark theme

### File Structure
```
├── app.py                 # Main Flask application with multi-server support
├── templates/
│   └── dashboard.html     # Dashboard HTML template
├── static/
│   └── style.css          # Stylesheet
├── pyproject.toml         # Python dependencies
└── replit.md              # This file
```

### Key Features
1. **Multi-Server Support**: Add unlimited X-UI panels
2. **Server Management**: Add, edit, delete, and test server connections
3. **Session-based Authentication**: Securely connects to each X-UI panel
4. **Multi-API Endpoint Support**: Works with different X-UI versions (Sanaei, original)
5. **Traffic Formatting**: Automatic byte-to-human conversion (KB, MB, GB, TB)
6. **Client Statistics**: Per-client traffic and expiry tracking
7. **Configurable Auto-refresh**: Toggle on/off with custom interval (seconds)
8. **Client Actions**:
   - Enable/Disable client
   - Reset traffic
   - Copy subscription link
   - Generate QR code

## Database Schema

### Servers Table
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| name | String(100) | Server display name |
| host | String(255) | X-UI panel URL |
| username | String(100) | Login username |
| password | String(255) | Login password |
| enabled | Boolean | Is server active |
| created_at | DateTime | Creation timestamp |

## API Endpoints

### Frontend
- `GET /` - Main dashboard page

### Server Management
- `GET /api/servers` - List all servers
- `POST /api/servers` - Add new server
- `PUT /api/servers/<id>` - Update server
- `DELETE /api/servers/<id>` - Delete server
- `POST /api/servers/<id>/test` - Test server connection

### Data
- `GET /api/refresh` - Returns JSON with updated data from all servers

### Client Actions
- `POST /api/client/<server_id>/<inbound_id>/<email>/toggle` - Enable/disable client
- `POST /api/client/<server_id>/<inbound_id>/<email>/reset` - Reset client traffic
- `GET /api/client/qrcode?link=<link>` - Generate QR code

## Recent Changes
- November 2025: Initial multi-server support
- Added PostgreSQL database for server storage
- Implemented configurable auto-refresh with toggle
- Added client action buttons (enable/disable, reset traffic)
- Added QR code and subscription link generation
- Built responsive dark-themed dashboard UI

## User Preferences
- Dark theme preferred
- Persian/Farsi support (bilingual)
- Clean, modern UI design
- Multi-server architecture
