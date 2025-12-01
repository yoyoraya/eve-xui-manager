# Eve - Xui Manager v1.0.0

## 🎉 First Official Release

### Major Features
- **Multi-Server Management**: Support for unlimited X-UI panels (Sanaei 3X-UI & Alireza X-UI)
- **Enterprise Security**: Rate limiting, secure cookies, password hashing, failed login logging
- **Sub Port Configuration**: Custom subscription port per server to avoid conflicts
- **QR Code Management**: Three QR codes per client (Subscription, JSON, Direct)
- **Global Client Search**: Search clients across all servers in real-time
- **Responsive Dashboard**: Professional UI with mobile support
- **Admin Management**: Superadmin can manage other administrators
- **Traffic Tracking**: Real-time upload/download statistics
- **Client Actions**: Enable/Disable, Reset Traffic, Renew with expiry options

### Security Features
- ✅ Rate limiting (5 login attempts per minute)
- ✅ Secure session management with HTTPONLY & SAMESITE flags
- ✅ PBKDF2 password hashing with salt
- ✅ Failed login attempt logging
- ✅ Environment-based configuration
- ✅ Input validation and sanitization

### Tech Stack
- Backend: Python 3.11 with Flask
- Database: PostgreSQL
- Frontend: HTML5, CSS3, Vanilla JavaScript
- Security: Werkzeug, Flask-Limiter

### Default Credentials
- **Username**: `admin`
- **Password**: From `INITIAL_ADMIN_PASSWORD` env var (default: `admin`)
- ⚠️ Change password after first login!

### Database Schema
- **Admins Table**: User management with secure password storage
- **Servers Table**: X-UI panel configurations with custom paths and ports
- **Sub Port Field**: New optional integer column for custom subscription ports

### Environment Variables Required
```
DATABASE_URL=postgresql://user:password@host/dbname
SESSION_SECRET=your_secret_key_here
INITIAL_ADMIN_PASSWORD=your_initial_password
```

### Known Limitations
- Rate limiting uses in-memory storage (suitable for single-server deployments)
- Session management is non-persistent across server restarts

### Installation & Setup
1. Clone the repository
2. Install dependencies: `pip install -r pyproject.toml`
3. Set environment variables
4. Run: `python app.py`
5. Access at: `http://localhost:5000`

### Support
For issues and feature requests, please open an issue on GitHub.

---
**Release Date**: December 1, 2025
**Status**: Stable
