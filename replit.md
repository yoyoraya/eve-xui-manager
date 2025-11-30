# X-UI Dashboard Monitor

## Overview
A web-based monitoring dashboard for X-UI VPN panels. This application connects to your X-UI server and displays:
- Inbound configurations with protocol, port, and status
- Traffic statistics (upload/download) in human-readable format
- Client information under each inbound
- Real-time data refresh functionality

## Project Architecture

### Tech Stack
- **Backend**: Python 3.11 with Flask
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Custom CSS with modern dark theme

### File Structure
```
├── app.py                 # Main Flask application
├── templates/
│   └── dashboard.html     # Dashboard HTML template
├── static/
│   └── style.css          # Stylesheet
├── requirements.txt       # Python dependencies
└── replit.md              # This file
```

### Key Features
1. **Session-based Authentication**: Securely connects to X-UI panel
2. **Multi-API Endpoint Support**: Works with different X-UI versions (Sanaei, original)
3. **Traffic Formatting**: Automatic byte-to-human conversion (KB, MB, GB, TB)
4. **Client Statistics**: Per-client traffic and expiry tracking
5. **Auto-refresh**: Updates data every 60 seconds

## Environment Variables Required
The following environment variables must be set:

| Variable | Description | Example |
|----------|-------------|---------|
| `XUI_HOST` | Full URL of your X-UI panel | `http://1.2.3.4:54321` |
| `XUI_USERNAME` | X-UI panel username | `admin` |
| `XUI_PASSWORD` | X-UI panel password | `your-password` |

## API Endpoints

### Frontend
- `GET /` - Main dashboard page

### API
- `GET /api/refresh` - Returns JSON with updated inbound and stats data

## Recent Changes
- Initial project setup (November 2025)
- Created Flask backend with X-UI API integration
- Built responsive dark-themed dashboard UI
- Added client statistics display with expandable sections

## User Preferences
- Dark theme preferred
- Persian/Farsi comments in original code (bilingual support)
- Clean, modern UI design
