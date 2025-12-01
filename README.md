# X-UI Dashboard Monitor - Multi Server

A professional web-based monitoring dashboard for multiple X-UI VPN panels with enterprise security features, secure authentication, and comprehensive statistics. Supports unlimited X-UI servers (Sanaei 3X-UI or Alireza X-UI).

## Features

### 🔐 Enterprise Security
- **Rate Limiting**: 5 login attempts per minute (brute-force protection)
- **Secure Cookies**: HTTPONLY and SAMESITE flags enabled
- **Password Hashing**: PBKDF2 encryption with salt
- **Failed Login Logging**: All attempts logged with IP addresses
- **Environment-Based Configuration**: Secure credential management

### 📊 Dashboard & Monitoring
- **Multi-Server Support**: Add unlimited X-UI panels
- **Auto-Detection**: Automatically detects Sanaei 3X-UI or Alireza X-UI panel types
- **Real-Time Statistics**: Server count, inbounds, clients, traffic overview
- **Responsive Design**: Mobile-friendly interface with hamburger menu
- **Auto-Refresh**: Configurable dashboard refresh intervals

### 👥 Client Management
- **Enable/Disable Clients**: Toggle client status
- **Reset Traffic**: Clear client data usage
- **Renew Clients**: Extend subscription with optional "Start after first use"
- **3-Type QR Codes**: Subscription, JSON, and Direct connection links
- **Subscription Links**: Customizable paths and ports per server

### 📱 Responsive UI
- **3-Column QR Grid** → 2-Column tablet → 1-Column mobile
- **Sidebar Navigation**: Collapsible on mobile
- **Touch-Friendly**: Optimized buttons and spacing
- **Dark Theme**: Professional dark mode interface

## Installation

### Requirements
- Python 3.11+
- PostgreSQL database
- Flask and dependencies

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/x-ui-dashboard-monitor.git
cd x-ui-dashboard-monitor
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```
Or if using uv:
```bash
uv pip install -r requirements.txt
```

3. **Setup environment variables**
```bash
export DATABASE_URL="postgresql://user:password@localhost/dbname"
export SESSION_SECRET="your-secret-key"
export INITIAL_ADMIN_PASSWORD="your-admin-password"
```

4. **Run the application**
```bash
python app.py
```

The dashboard will be available at `http://localhost:5000`

## Default Credentials

- **Username**: `admin`
- **Password**: From `INITIAL_ADMIN_PASSWORD` env var (default: `admin`)
- ⚠️ **Change password immediately after first login!**

## Configuration

### Environment Variables

**Required:**
- `DATABASE_URL` - PostgreSQL connection string

**Security:**
- `SESSION_SECRET` - Flask session secret key
- `INITIAL_ADMIN_PASSWORD` - Initial admin password (default: "admin")

**Optional:**
- `XUI_HOST` - Default X-UI panel host
- `XUI_USERNAME` - Default X-UI username
- `XUI_PASSWORD` - Default X-UI password

### Server Configuration

Each X-UI server can be configured with:
- **Name**: Display name for the server
- **Host**: X-UI panel URL
- **Credentials**: Username and password
- **Panel Type**: Auto-detect, Sanaei 3X-UI, or Alireza X-UI
- **Subscription Path**: Custom subscription endpoint (default: `/sub/`)
- **JSON Path**: Custom JSON endpoint (default: `/json/`)
- **Subscription Port**: Optional custom port for subscriptions

## API Endpoints

### Authentication
- `GET/POST /login` - Login page (rate limited: 5/min)
- `GET /logout` - Logout

### Pages
- `GET /` - Dashboard
- `GET /servers` - Server management
- `GET /admins` - Admin management

### Client Operations
- `POST /api/client/<server_id>/<inbound_id>/<email>/toggle` - Enable/disable client
- `POST /api/client/<server_id>/<inbound_id>/<email>/reset` - Reset traffic
- `POST /api/client/<server_id>/<inbound_id>/<email>/renew` - Renew client
- `GET /api/client/qrcode` - Generate QR code

### Server Management
- `GET/POST /api/servers` - List/create servers
- `PUT /api/servers/<id>` - Update server
- `DELETE /api/servers/<id>` - Delete server
- `POST /api/servers/<id>/test` - Test connection

### Admin Management
- `GET /api/admins` - List admins
- `POST /api/admins` - Create admin
- `PUT /api/admins/<id>` - Update admin
- `DELETE /api/admins/<id>` - Delete admin

## Project Structure

```
.
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
├── README.md                # This file
└── replit.md                # Technical documentation
```

## Database Schema

### Admins Table
- `id` - Primary key
- `username` - Unique username
- `password_hash` - PBKDF2 hashed password
- `is_superadmin` - Can manage other admins
- `enabled` - Account active status
- `created_at` - Creation timestamp
- `last_login` - Last login time

### Servers Table
- `id` - Primary key
- `name` - Server display name
- `host` - X-UI panel URL
- `username` - Login username
- `password` - Login password
- `enabled` - Is server active
- `panel_type` - auto/sanaei/alireza
- `sub_path` - Subscription path (default: /sub/)
- `json_path` - JSON path (default: /json/)
- `sub_port` - Optional subscription port
- `created_at` - Creation timestamp

## Security Considerations

- All passwords are hashed with PBKDF2 algorithm
- Rate limiting prevents brute-force attacks
- Session cookies are secure and HTTP-only
- CSRF protection with SameSite cookies
- Failed login attempts are logged for audit trails
- Environment variables protect sensitive credentials
- No secrets in version control

## Browser Support

- Chrome/Edge: ✅ Latest versions
- Firefox: ✅ Latest versions
- Safari: ✅ Latest versions
- Mobile browsers: ✅ iOS Safari, Chrome Android

## License

MIT License - See LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For issues and feature requests, please open an issue on GitHub.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

**Made with ❤️ for VPN administrators worldwide**
