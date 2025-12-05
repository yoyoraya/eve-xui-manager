# Eve - Xui Manager

A professional web-based monitoring dashboard for multiple X-UI VPN panels with enterprise security features, secure authentication, and comprehensive statistics. Supports unlimited X-UI servers (Sanaei 3X-UI or Alireza X-UI).

un the following command on your Ubuntu/Debian server:
## 🚀 Installation (One-Command)
Run the following command on your Ubuntu/Debian server:
```bash
bash <(curl -Ls https://raw.githubusercontent.com/yoyoraya/eve-xui-manager/main/setup.sh)
```
## Features

### 🔐 Enterprise Security
- **Rate Limiting**: 5 login attempts per minute (brute-force protection)
- **Secure Cookies**: HTTPONLY + SAMESITE flags on every session
- **Password Hashing**: PBKDF2 with per-user salt
- **Failed Login Logging**: Every attempt is stored with IP metadata
- **Environment-Driven Secrets**: No credentials inside the repo

### 📊 Unified Operations Dashboard
- **Unlimited Servers**: Attach any number of Sanaei 3X-UI or Alireza X-UI panels
- **Auto Detection**: Panel type, subscription/json paths, and protocols are detected automatically
- **Actionable Tables**: Toggle clients, expand QR codes, assign owners, and inspect traffic from one grid
- **Global Search & Auto Refresh**: Find a client in milliseconds and keep stats synced on a timer
- **Health Visibility**: Inline error toasts for unreachable panels + per-server failure notes

### 💼 Wallet & Billing Automation
- **Prepaid Wallets**: Live wallet pill shows the reseller balance everywhere in the UI
- **Package Marketplace**: Define bundles (days/GB/price) and let resellers buy or renew with one click
- **Custom Tariffs**: When no package is selected, pricing automatically uses configurable cost-per-day and cost-per-GB baselines
- **Paid Renew/Reset Flow**: Modal confirmation displays the deduction before charging the wallet; reset traffic now consumes billable GB
- **Transaction Ledger**: Dedicated `/transactions` page + `/api/transactions` endpoint for auditing every wallet movement

### 👥 Client Lifecycle & Reseller Controls
- **Purchase New Service**: Modern modal covers package purchase or fully custom plans, including "start after first use"
- **Renew Clients**: Same experience as purchase—optionally reuse packages or enter free-form day/volume values
- **Reset Traffic**: Costs are enforced server-side, and ownership rules ensure resellers cannot touch foreign clients
- **Ownership & Allowed Servers**: Assign clients to resellers and restrict which servers each reseller can see or charge
- **Link Delivery**: Generate subscription, JSON, direct, and dashboard QR codes optimized for mobile scanning

### 📱 Responsive Experience
- **Touch-Ready Modals**: All dialogs (purchase, renew, reset, assign) respect mobile breakpoints
- **Adaptive Grids**: QR and action grids collapse gracefully from desktop to phones
- **Collapsible Sidebar**: Smooth hamburger interaction for tablets/phones
- **Unified Dark Theme**: Consistent colors, glassmorphism cards, and status pills across pages

## Installation

### Requirements
- Python 3.11+
- PostgreSQL database
- Flask and dependencies

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/eve-xui-manager.git
cd eve-xui-manager
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
- `GET /admins` - Admin management (superadmin only)
- `GET /packages` - Configure packages/base tariffs (superadmin)
- `GET /transactions` - Wallet ledger for every admin/reseller
- `GET /sub-manager` - Curate downstream subscription app configs (superadmin)

### Client Operations
- `POST /api/client/<server_id>/<inbound_id>/add` - Create a client (package or custom pricing)
- `POST /api/client/<server_id>/<inbound_id>/toggle` - Enable/disable client (email passed in JSON)
- `POST /api/client/<server_id>/<inbound_id>/reset` - Paid traffic reset with wallet deduction
- `POST /api/client/<server_id>/<inbound_id>/<email>/renew` - Renew client (package/custom)
- `GET /api/client/qrcode` - Generate QR codes for links
- `GET /api/clients/search` - Global search by email/username
- `POST /api/assign-client` - Assign ownership to a reseller (superadmin)

### Server Management
- `GET/POST /api/servers` - List/create servers
- `PUT /api/servers/<id>` - Update server
- `DELETE /api/servers/<id>` - Delete server
- `POST /api/servers/<id>/test` - Test connection

### Packages & Pricing
- `GET /api/packages` - Public list used by purchase/renew modals
- `POST /admin/packages` - Create package (superadmin)
- `PUT /admin/packages/<id>` - Update package (superadmin)

### Wallet & Transactions
- `GET /api/transactions` - List wallet transactions (optionally filter by `user_id`)
- `GET /api/sub-apps` - Fetch Sub-app configuration cards for the Sub Manager page

### Admin Management
- `GET /api/admins` - List admins
- `POST /api/admins` - Create admin
- `PUT /api/admins/<id>` - Update admin
- `DELETE /api/admins/<id>` - Delete admin

## Project Structure

```
.
├── app.py                  # Primary Flask app (routes, billing logic, APIs)
├── main.py                 # Lightweight entry/helper (used by some deployments)
├── setup.sh                # 1-line installer for Ubuntu/Debian
├── pyproject.toml / uv.lock# Python deps + exact locking
├── templates/              # Jinja2 views
│   ├── base.html           # Layout + sidebar + wallet pill
│   ├── dashboard.html      # Main dashboard, modals, JS helpers
│   ├── login.html          # Auth screen
│   ├── admins.html         # Admin/reseller management (superadmin)
│   ├── servers.html        # Server CRUD UI
│   ├── packages.html       # Configure packages & base tariffs
│   ├── transactions.html   # Wallet ledger table
│   ├── sub_manager.html    # Downstream subscription-app manager
│   ├── subscription.html   # Public subscription landing page
│   └── error.html          # Friendly error surface
├── static/
│   └── style.css           # Unified dark theme + responsive styles
├── instance/               # SQLite DB / config when running locally
├── attached_assets/        # Design specs, screenshots, pasted assets
├── README.md               # You are here
├── INSTALL.md / RELEASE_NOTES.md / CHANGELOG.md
└── replit.md               # Cloud-dev specific notes
```


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
