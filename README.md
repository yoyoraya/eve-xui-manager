# 🛡️ Eve — X-UI Manager

> A professional, multi-tenant control panel that unifies **unlimited X-UI VPN servers** into one dashboard — with a full **reseller billing system**, **SMS & WhatsApp automation**, financial reporting, and self-healing operations. Works with **Sanaei 3X-UI** and **Alireza X-UI** panels.

🌐 Built for Iranian operators: **Jalali (Persian) calendar** and **Asia/Tehran** time throughout. 🇮🇷

---

## ✨ Why Eve?

- 🧩 **One dashboard for every panel** — attach any number of Sanaei/Alireza servers; panel type, sub/JSON paths and protocols are **auto-detected**.
- 💰 **A complete reseller economy** — prepaid wallets, packages, custom tariffs, ownership rules, and a full **financial statement** per reseller.
- 📲 **Hands-off customer messaging** — **SMS & WhatsApp automation** for create, renew, low-volume, near-expiry, expired and volume-ended events.
- 🩺 **Runs itself** — a **self-healing health watchdog**, Redis-shared background workers, and automatic DB migrations.
- 📱 **Mobile-first** — every page, modal and table is responsive, with a unified dark theme.

---

## 🚀 Installation (One-Command)

Run on your Ubuntu/Debian server:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/yoyoraya/eve-xui-manager/main/setup.sh)
```

The installer self-updates, verifies and installs requirements, and brings the service up behind nginx + gunicorn.

### 🐳 Docker / Offline Deployment

For production or restricted/offline servers, use Docker. GitHub Actions builds the image and publishes it to GHCR, so the **target server needs no GitHub, PyPI, or apt access** after the images are transferred. See [DOCKER.md](DOCKER.md).

Build a transferable bundle on an online server:

```bash
bash scripts/docker/build-offline-bundle.sh
```

---

## 🌟 Features

### 🔐 Enterprise Security

- **Brute-force protection**: 5 login attempts per minute, rate-limited.
- **Secure sessions**: `HTTPONLY` + `SAMESITE` cookies on every request.
- **Strong password hashing**: PBKDF2 with per-user salt.
- **Audit-ready**: every failed login is stored with IP metadata.
- **No secrets in the repo**: all credentials are environment-driven.

### 📊 Unified Operations Dashboard

- **Unlimited servers**: attach any number of Sanaei 3X-UI / Alireza X-UI panels.
- **Auto-detection**: panel type, subscription/JSON paths, and protocols detected for you.
- **Actionable grid**: toggle clients, expand QR codes, assign owners, and inspect traffic from one table.
- **Instant global search & auto-refresh**: find any client in milliseconds, stats stay synced on a timer.
- **Live health visibility**: inline error toasts for unreachable panels + per-server failure notes.

### 💼 Reseller Economy, Wallets & Billing

- **Prepaid wallets**: a live balance pill follows the reseller everywhere in the UI.
- **Package marketplace**: define bundles (days / GB / price) and let resellers buy or renew in one click.
- **Custom tariffs**: with no package selected, pricing falls back to configurable cost-per-day and cost-per-GB tiers.
- **Guarded paid flows**: renew/reset show the deduction before charging; costs are enforced **server-side**.
- **Ownership & allowed servers**: assign clients to resellers and restrict which servers each one can see or charge.

### 🧾 Finance & Reseller Statements

- **Per-reseller statement**: pick a reseller + a Jalali date range and see exactly how many accounts they **created / renewed / reset**.
- **"Should-deposit" accounting**: total spent vs. actually deposited, with a clear **owes / credit balance**.
- **Drill-down by package**: expand any package to list every user, their GB/days, cost, and a 🎁 **gift** flag.
- **Breakdowns & export**: by package and by server, with **CSV export** and a full transaction ledger.

### 📲 SMS Automation (GMweb gateway)

- **Event-driven**: auto-send on **account creation** and **renewal**, using your own templates.
- **State-based reminders**: a periodic scan messages each non-reseller account on ⚠️ low volume, ⏳ near expiry, ⛔ expired, and 🚫 volume-ended.
- **Smart cooldowns**: a **per-state resend gap (hours), shared across SMS + WhatsApp**, that survives restarts and **resets on renewal**.
- **🌙 Quiet hours (Asia/Tehran)**: pause the reminder scan overnight — while **create/renew confirmations still send immediately**.
- **Age cutoffs**: stop nagging long-expired or long-ended accounts after a configurable number of days.
- **Opt-out tags**: a `#nosms` / `#nopm` tag in a client's comment is always honored (auto-toggled when you disable/enable a client).
- **Send queue & log**: live progress, priority ordering, rate-limit / 429 back-off, and a **paginated, Jalali-timestamped** send log.

### 💬 WhatsApp Automation

- **Welcome / renew / pre-expiry** triggers via a Baileys/OpenWA gateway.
- **Warm-up & pacing** controls, daily limits, and a circuit breaker for safe sending.
- **Region-aware**: cleanly disabled when the panel is deployed inside Iran.

### 📡 Monitor & 👑 Royalty

- **Monitor**: per-state message templates and live service-state alerts (soon / low / expired / ended) that the SMS & WhatsApp automation reuse.
- **Royalty**: re-engagement messaging for idle accounts that haven't connected yet.

### 👥 Client Lifecycle

- **Purchase / renew**: a modern modal for package or fully custom plans, including "start after first use" and **gift volume**.
- **Reset traffic**: billed server-side; ownership rules stop resellers touching foreign clients.
- **Link delivery**: subscription, JSON, direct, and dashboard QR codes optimized for mobile scanning.

### 🔒 SSL, 🩺 Health & 📈 Traffic

- **SSL toolkit**: sync from LetsEncrypt, export a bundle, upload it to another server, and apply to nginx — **HTTPS instantly**.
- **Self-healing watchdog**: monitors DB, servers, disk and static files every 60s, with a logged action trail.
- **Traffic Check**: per-server / per-inbound usage over Today / 7 / 30 days, from usage snapshots.
- **Supported Apps manager**: curate the V2Ray client apps shown on the subscription page.

### 📱 Responsive Experience

- **Touch-ready modals** and **adaptive grids** that collapse gracefully from desktop to phone.
- **Collapsible sidebar** and a **unified dark theme** with glassmorphism cards and status pills.

### ⚙️ Operations & Reliability

- **Multi-worker ready**: gunicorn with **Redis-shared** scan progress and cancel signals across workers.
- **Zero-downtime schema updates**: columns/tables are auto-migrated on startup.
- **Compressed responses**: gzip/brotli to keep large payloads fast.

---

## 🛠️ Manual Installation

### Requirements

- 🐍 Python 3.11+
- 🐘 PostgreSQL
- 🧰 Redis (recommended, for multi-worker background jobs)

### Setup

1. **Clone**
```bash
git clone https://github.com/yoyoraya/eve-xui-manager.git
cd eve-xui-manager
```

2. **Install dependencies**
```bash
pip install -r requirements.txt   # or: uv pip install -r requirements.txt
```

3. **Environment variables**
```bash
export DATABASE_URL="postgresql://user:password@localhost/dbname"
export SESSION_SECRET="your-secret-key"
export INITIAL_ADMIN_PASSWORD="your-admin-password"
```

4. **Run**
```bash
python app.py
```

The dashboard is available at `http://localhost:5000`.

---

## 🔑 Default Credentials

- **Username**: `admin`
- **Password**: from `INITIAL_ADMIN_PASSWORD` (default: `admin`)
- ⚠️ **Change the password immediately after first login!**

---

## ⚙️ Configuration

### Environment Variables

**Required**
- `DATABASE_URL` — PostgreSQL connection string

**Security**
- `SESSION_SECRET` — Flask session secret key
- `INITIAL_ADMIN_PASSWORD` — initial admin password (default: `admin`)

**Optional**
- `REDIS_URL` — enable cross-worker background jobs and shared scan state
- `XUI_HOST` / `XUI_USERNAME` / `XUI_PASSWORD` — default X-UI panel host & credentials

### Per-Server Settings

- **Name**, **Host**, **Credentials**
- **Panel Type**: Auto-detect / Sanaei 3X-UI / Alireza X-UI
- **Subscription Path** (default `/sub/`), **JSON Path** (default `/json/`), **Subscription Port** (optional)

---

## 🗂️ Project Structure

```
.
├── app.py                  # Primary Flask app (routes, billing, automations, APIs)
├── setup.sh                # One-line installer for Ubuntu/Debian
├── pyproject.toml / uv.lock# Python deps + exact locking
├── templates/              # Jinja2 views
│   ├── base.html           # Layout + sidebar + wallet pill
│   ├── dashboard.html      # Main dashboard, client modals, JS helpers
│   ├── monitor.html        # Service-state monitor + message templates
│   ├── royalty.html        # Re-engagement messaging
│   ├── finance.html        # Finance overview + reseller statement
│   ├── transactions.html   # Wallet ledger
│   ├── receipts.html       # Deposit receipts & approval
│   ├── bank_cards.html     # Destination cards
│   ├── packages.html       # Packages & base tariffs
│   ├── reseller_packages.html
│   ├── servers.html        # Server CRUD UI
│   ├── admins.html         # Admin/reseller management (superadmin)
│   ├── settings.html       # SMS/WhatsApp automation, SSL, health, traffic, apps
│   ├── sub_manager.html    # Supported-apps / subscription manager
│   ├── subscription.html   # Public subscription landing page
│   ├── client_portal.html  # End-user portal
│   └── error.html          # Friendly error surface
├── static/                 # Unified dark theme + responsive styles, assets
├── graphify-out/           # Code knowledge graph (architecture map)
├── DOCKER.md / INSTALL.md / CHANGELOG.md / RELEASE_NOTES.md
└── README.md               # You are here
```

---

## 🌐 Browser Support

- Chrome / Edge: ✅ latest
- Firefox: ✅ latest
- Safari: ✅ latest
- Mobile: ✅ iOS Safari, Chrome Android

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🆘 Support

For issues and feature requests, please open an issue on GitHub.

## 🗒️ Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

**Made with ❤️ for VPN administrators worldwide**
