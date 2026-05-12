# Eve - Xui Manager v1.9.1

## [1.9.1] - 2026-05-12

### ✨ New Features

#### Server Panel Information Display
- **Dashboard Enhancements**: Server list now displays real-time panel information:
  - Xray version badge
  - X-UI/3X-UI version indicator
  - Panel type badge (3X-UI, X-UI)
  - Xray state indicator (running/stopped) with color coding
  - Real-time status with loading indicators and error states
  
#### Quick Panel Info API Endpoint
- **New `/api/servers/<id>/panel-info` endpoint**: Fast, non-blocking panel status fetch
  - Logs in and fetches version/state info immediately after server addition
  - Updates in-memory cache for instant UI reflection
  - Designed for immediate post-add-server verification
  - Returns: panel_type, xui_version, xray_version, xray_state, xray_core

#### Settings Overview Dashboard
- **New `/api/settings/overview` endpoint**: System health and status information
  - Uptime tracking
  - Last backup timestamp
  - Last Telegram backup timestamp
  - Database type and connection info
  - Current vs latest version comparison
  - SSL certificate info with expiration and issuer details
  - Update availability indicator

### 🔧 Technical Improvements

- **Reverse Proxy Support**: Added Werkzeug ProxyFix middleware to properly handle SSL termination from Nginx/reverse proxies
  - Corrects scheme (HTTP/HTTPS) detection
  - Preserves host header integrity
  - Enables single proxy hop configuration (x_for=1, x_proto=1, x_host=1, x_prefix=1)
  
- **Server Status Caching**: Improved in-memory cache sync for immediate UI updates
- **Error Handling**: Better error messaging for unreachable servers
- **HTML Escaping**: Enhanced XSS protection in dashboard template rendering

### 🐛 Bug Fixes

- Fixed server list refreshing after server addition
- Improved async/await handling in server addition workflow
- Better handling of uninitialized panel info states

### 📝 Notes

- All new endpoints follow existing authentication patterns (@login_required)
- Server panel info can be refreshed on-demand via dashboard button
- SSL certificate information uses /etc/letsencrypt and /etc/ssl/eve-manager detection
- ProxyFix configuration supports standard Nginx SSL termination setups
