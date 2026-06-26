# Changelog - Eve

All notable changes to Eve - Xui Manager are documented in this file.

## [Unreleased]

## [2.4.0] - 2026-06-26

> Big release since **2.3.0** — a whole new **SMS Automation** subsystem, **3x-ui v3.4+** support, reseller **finance statements**, and major dashboard **performance** work.

### 📲 SMS Automation — new subsystem (GMweb / Google Messages gateway)
- **Automated SMS** on **create**, **renew**, and **near-depletion** (low-volume / near-expiry / expired / volume-ended) — using your own SMS templates, so an automated text reads exactly like a manual one
- **👑 Royalty SMS**: nudge owner-less *idle* accounts (active but zero traffic in the window). A **cap-fair queue** drains huge lists over several days — each user exactly once, every send & skip logged
- **🧾 Send queue & live log**: paginated, **Jalali + Asia/Tehran** timestamps, auto-refreshes every 5s, `no-store` (always fresh), and shared across gunicorn workers via Redis
- **🧪 Send Test SMS** to the superadmin / panel contact number · **Start now** / **Stop & disable** · live scan progress + cancel
- **🌙 Quiet hours** (Asia/Tehran): hold reminder SMS overnight and flush after the window — create/renew confirmations always go out immediately
- **⏱️ Fairness & safety**: per-state hourly cooldown shared with WhatsApp (no double-ping, reset on renewal), global send pace + **HTTP 429 backoff**, and an **Idempotency-Key** so retries never double-send
- **🔒 Owner gating**: only owner-less (system/superadmin) accounts are messaged — reseller-owned accounts are never texted from the system number
- **🚫 Opt-out tags** `#nosms` / `#nopm` in the client comment suppress messaging; manual **disable** adds them, **enable/renew** strips them
- Options: skip unlimited accounts, expired max-age cap, volume-ended cutoff

### 🧩 3x-ui v3.4 / v3.4.1 compatibility
- **Account creation now works on v3.4+ panels** (node-hosted inbounds): client payload defaults `security=auto`. v3.4 made that field required — its absence made the panel silently drop the new client (empty 200)
- Renew / disable / read / subscription / online detection verified working on v3.4.1

### 💰 Reseller Finance
- **Reseller statement**: accounts / cost / packages with **per-package drill-down** (gift + GB/days fallback) and a **"should-deposit"** figure

### 🔐 Reseller Permissions
- **Free creation/renew/reset** gated behind a per-user permission
- **Per-reseller WhatsApp automation** permission

### ⚡ Performance
- **Progressive, server-by-server dashboard load** — no more waiting for every panel before anything shows
- Removed the per-request **deepcopy** on the `/api/refresh` hot path
- **gzip/br compression** to shrink large `/api/refresh` payloads

### 🛠️ Fixes & polish
- **Renew** surfaces the **real panel error** on HTTP 400 (e.g. *Duplicate subId*) instead of a generic message
- **"Assigned inbounds"** now shows reliably for v3 servers in Edit Client
- Fixed a **500 on /admins** (an escaped apostrophe broke a Jinja string)
- **Settings** fully responsive on mobile + no horizontal overflow at desktop widths (e.g. 1440px)
- **setup.sh** prunes old app-dir backups on update so `/opt` stops filling
- Subscription page loads **all inbounds** for v3 multi-inbound clients
- **i18n**: reseller permission labels localized by panel language
- Online update auto-verifies and installs requirements

## [2.3.2] - 2026-06-20

### 📱 WhatsApp Automation Scope
- **Per-reseller automation permission**: New "WhatsApp Automation Enabled" toggle in each reseller's user settings (default OFF). The system no longer messages a reseller's clients from the owner's WhatsApp number unless that reseller is explicitly opted in
- **Scoped near-depletion scan**: Background depletion scanner skips accounts owned by resellers who haven't enabled automation
- **Scoped renew auto-send**: Automatic post-renewal WhatsApp message is suppressed for reseller-owned accounts without the permission
- Accounts owned by the system owner / admins / superadmins are always eligible (unchanged behavior)

## [2.3.1] - 2026-06-20

### 🔒 Reseller Permissions
- **Free creation/renew gating**: The "Free" toggle (new purchase, renewal, and traffic reset) is now hidden from resellers unless explicitly enabled per-user. A new "Allow Free Creation" switch in the reseller's user settings controls it
- **Server-side enforcement**: All three free-action endpoints reject `is_free` requests with HTTP 403 for resellers without the permission — the toggle cannot be bypassed client-side
- Admins/superadmins are unaffected (they never consume credit)

## [2.3.0] - 2026-06-20

### 🤖 WhatsApp Bot (OpenWA)
- **OpenWA self-hosted gateway**: Integrate Eve with OpenWA as an alternative to Baileys — send WhatsApp messages through your own local server without relying on the cloud
- **Warm-up mode**: Linear ramp-up of the daily send cap over N days so new WhatsApp sessions aren't flagged for sudden volume spikes
- **Near-depletion bot**: Background scanner (every 30 min) that automatically messages clients whose subscription volume or time is running low; configurable thresholds, cooldown, and dedup via database log
- **Bot templates**: Dedicated WhatsApp message templates for Created, Renew, Ended, and Info events — separate from SMS templates with their own placeholders
- **Pace gate**: Optional minimum gap + random jitter between any two WhatsApp sends to mimic human pacing (off by default)
- **Ban-risk warning banner**: Displays a prominent warning when OpenWA provider is selected with recommendations for safe usage
- **Session UUID resolver**: Automatically resolves OpenWA session names to internal UUIDs (with 5-minute cache) to work around OpenWA's runtime engine indexing by UUID not name

### 📊 Monitor Overhaul
- **Zero-usage badge & royalty extend**: Idle clients now shown with a distinct chip; royalty information template can be sent directly from the monitor table
- **Message send counter**: Per-client SMS/WhatsApp send count visible in the monitor row
- **`{dashboard_link}` & `{sub_link}` fixed**: These placeholders were empty in monitor alert messages — now correctly populated from cached client data
- **Royalty template fallback chain**: Monitor now tries the royalty template first, then the standard template, with a proper reset of send counter on renewal
- **No-usage template field**: Added directly in monitor settings (no longer buried)
- **Default filters**: Monitor now defaults to Low+Soon only (reseller users hidden) on first load
- **Deduplication**: Same user on multiple inbounds shown once per server; ended/expired clients always restored regardless of enable flag
- **Time-expiry priority**: Expiry by time takes priority over volume-ended status
- **Responsive layout**: Fixed monitor table layout for Surface/tablet widths (1101–1500px)
- **Add Days modal**: Translated to English; counter resets on any renewal (dashboard or bulk)

### 📝 Templates
- **WhatsApp/SMS variants**: Dedicated Created and Renew templates for WhatsApp and SMS with send test buttons
- **Conditional gift blocks**: `{if_gift}…{/if_gift}` and `{gift_volume}` placeholders available in all template editors
- **Account-info variables**: `{telegram_channel}`, `{whatsapp_channel}`, and all account-info placeholders now resolved correctly by role in Created/Renew sends
- **Unresolved placeholder cleanup**: All `{…}` tokens that don't match any variable are stripped before sending

### ⚙️ 3x-ui v3 Compatibility
- **v3.3.1 CSRF support**: Fetch `X-CSRF-Token` before login so Eve works with panels that have CSRF middleware enabled (fully backward compatible)
- **http→https self-heal**: Server saved with `http://` automatically retried over `https://` when the panel is SSL-only
- **Spaced email handling**: Emails with spaces are renamed on the panel before any add/update/delete/renew operation; search and dedup handle spaced emails correctly
- **Session cache invalidation**: Cached panel session cleared when a server's auth mode changes
- **v3 Last User**: Shows recent clients only for the checked inbounds, refreshed on toggle, deduplicated

### 🚀 Dashboard & Performance
- **Lazy row mount**: Phase 3 incremental render — rows mount in chunks so the dashboard is interactive before all data arrives
- **Write-through cache**: Edits and renewals update the in-memory cache instantly; no stale data after panel operations across all panel types
- **Persian/Arabic digit search**: Search box converts Persian/Arabic digits to ASCII automatically
- **"Why?" error modal**: Server cards now have a button explaining fetch errors in plain language
- **Volume stats button**: Added to v3 server cards for quick traffic overview

### 💾 Backup & Migration
- **Upload progress UI**: Real-time progress bar during backup restore upload
- **512MB upload limit**: Raised from the old limit to support large database bundles
- **X-Accel-Redirect streaming**: Large backup downloads stream through Nginx to avoid Gunicorn timeout
- **Migration fixes**: Schema reset before pg restore; sync of `static/app-files` and `static/uploads` from old server

### 📢 Announcements
- **Media upload in editor**: Inline image/video upload directly in the announcement message editor
- **Popup modal type**: New announcement type that opens as a modal with a custom button label

### 🔒 SSL
- **Nginx auto-reload on renewal**: SSL renewal now reloads Nginx automatically (fixed 500 error when cert destination was root-owned)
- **Cert classification fix**: Certs classified by issuer vs. subject, not file path, so self-signed and CA certs are identified correctly

### 🎯 Royalty
- **Deduplication**: Idle list deduped by email-per-server (v3 multi-inbound)
- **Synchronous scan**: Replaced fragile background-job scan with synchronous execution on the index request
- **Index snapshots**: Constant-cost baseline scan regardless of window size

### 🛠 Other Fixes
- **Backup Database button**: Added to server management cards on the Servers page
- **Reseller owner badges**: Multi-select owner filter for admin on the Packages page
- **Subscription history**: Compact inline renewal line; paginated history table (10/page); renewal days marked in table
- **Ownership anchor**: Client owner anchored to panel UUID so server/inbound edits don't lose ownership
- **Email auto-sanitize**: Email field in Add Client modal strips illegal characters on input
- **Emoji on iOS**: Emoji in messages now preserved correctly on iOS devices
- **SSL auto-apply after upload**: SSL cert applied automatically after upload completes
- **Server list refresh**: Server list no longer stale after editing a server
- **Pricing fix**: Dynamic tier price no longer overwritten by package loader on re-open
- **Shadowsocks fix**: Non-v3 update/delete operations restored for Shadowsocks protocol

### 🐛 Bug Fixes & Improvements
- **3x-ui v3.3.1 compatibility (CSRF)**: v3.3.1 added a CSRF middleware in front of `POST /login` (and every other cookie-session state-changing route), so EVE could no longer log in to upgraded panels — cookie-login servers returned `403`, which surfaced as `502 Bad Gateway` on the EVE subscription page when the client wasn't cached. EVE now fetches a token from `GET {basePath}/csrf-token` and pins it as the `X-CSRF-Token` header on the panel session before logging in, so login and all later `/panel/api/*` POSTs (add/update/delete client, reset traffic, backup, onlines) pass the guard. Verified live against a v3.3.1 panel (login `success:true` with the token, `403` without it). Fully backward compatible: older panels (≤3.3.0, v3, pre-v3) have no `/csrf-token` route and ignore the header, and API-token (Bearer) servers are unaffected (CSRF is bypassed for token auth).
- **HTTPS-only panel self-heal**: A server saved with an `http://` host pointing at an SSL-enabled panel (HSTS + Secure cookies) failed with a bare `ConnectionError` shown as "Error testing connection". Testing a server now auto-detects this and rewrites the host to `https://` when — and only when — https answers and http does not, so plaintext panels are left untouched.

## [1.4.2] - 2025-12-12

### 🐛 Bug Fixes & Improvements
- **Reseller Visibility**: Fixed issue where clients were hidden from resellers due to missing inbound IDs (implemented loose matching).
- **Traffic Formatting**: Improved traffic display to dynamically show KB/MB/GB/TB units.
- **UI Alignment**: Fixed action button alignment on desktop (right-aligned) and mobile (left-aligned).
- **Server List**: Fixed bug where server list in modals would be empty after status updates.
- **Search Autofill**: Implemented fix to prevent browser autofill on the search input.

## [1.4.1] - 2025-12-11

### ✨ Protocol Link Support
- Full support for direct client links for all 3x-ui protocols (vmess, vless, trojan, shadowsocks) with proper ws/grpc/tcp, TLS/Reality, and plugin parameters.
- Improved link generation logic for all supported protocols.

### 🐛 Bug Fixes & Improvements
- Webpath fixes for custom panel paths (login, API, panel URLs).
- Expiry display and UI tweaks.
- Version and tag update logic improvements.

## [1.3.0] - 2025-12-09

### ✨ New Features
- **FAQ Platform Support**: Added ability to categorize FAQs by platform (Android, iOS, Windows).
- **FAQ Editor**: Enhanced FAQ editor with RTL/LTR support and improved toolbar.
- **Subscription Page**: Added platform filtering for Apps and FAQs.

### 🎨 UI/UX Improvements
- **Upload UI**: Redesigned file upload inputs with a modern button-and-spinner style.
- **Dropdowns**: Standardized OS and Platform selection to use consistent dropdown components on the Subscription page.
- **Icons**: Added platform-specific icons to selection menus.

## [1.2.1] - 2025-12-06

### ✨ New Features
- **Settings Page**: Introduced a dedicated settings area for managing application configurations.
- **Notification Templates**: Added a system to create and manage dynamic text templates for client creation notifications.
- **Backup & Restore**: Implemented full database backup and restore functionality with download/delete options.

### 🎨 UI/UX Improvements
- **Card Design**: Updated template management to use a modern card-based layout.
- **Number Formatting**: Applied global thousands separators for better readability of prices and volumes.
- **Visual Polish**: Improved button styles, spacing, and hover effects in the Settings and Backup sections.

## [1.2.0] - 2025-12-06

### ✨ New Features
- **Version Checking**: Added automatic version checking against GitHub Releases.
- **New Client Modal**: Enhanced success modal with QR codes and copyable subscription details.
- **Transaction Logging**: Expanded transaction logging to include Admin actions when costs are involved.

### 🎨 UI/UX Improvements
- **Renew Modal**: Redesigned to match the Purchase modal layout for consistency.
- **Receipts UI**: Improved card selection with a grid layout and copy-to-clipboard functionality.
- **Typography**: Standardized Persian text using the "Vazirmatn" font.
- **Sidebar**: Added a "New Release" badge with visual indicators.

### 🐛 Bug Fixes
- Fixed `TemplateAssertionError` in `base.html`.
- Resolved issue where Admin transactions were not being logged in history.

## [1.0.0] - 2024-12-01

### 🎉 Initial Release

This is the first stable release of Eve - Xui Manager with comprehensive features for managing multiple X-UI VPN panels.

### ✨ Features

#### Security
- Rate limiting: 5 login attempts per minute to prevent brute-force attacks
- Secure cookies with HTTPONLY and SAMESITE flags
- PBKDF2 password hashing with salt
- Failed login attempt logging with IP addresses
- Environment-based configuration for sensitive credentials
- Session timeout after 7 days
- Superadmin role for admin management

#### Dashboard
- Multi-server support (unlimited X-UI panels)
- Auto-detection of panel types (Sanaei 3X-UI vs Alireza X-UI)
- Real-time statistics: servers, inbounds, clients, traffic
- Responsive sidebar navigation
- Mobile-friendly hamburger menu
- Configurable auto-refresh intervals
- Manual refresh button

#### Client Management
- Enable/disable clients
- Reset client traffic
- Renew clients with configurable days and volume
- "Start after first use" option for subscriptions
- 3-Type QR Codes per client:
  - Subscription QR Code (Copy Sub)
  - Subscription JSON QR Code (Copy JSON)
  - Direct Connection Link QR Code (Copy Direct)

#### Server Configuration
- Add/edit/delete X-UI servers
- Customizable subscription paths per server
- Customizable JSON paths per server
- Custom subscription ports (with fallback to panel port)
- Connection testing

#### Admin Management
- Create/edit/disable admin accounts
- Superadmin can manage other admins
- Last login timestamp tracking
- Enable/disable accounts without deletion

#### UI/UX
- Professional dark theme
- Responsive grid layouts
- Color-coded expiry badges (green/yellow/red)
- Jalali calendar dates
- Traffic display (upload ↑ / download ↓)
- Volume information (used / total)
- Optimized for mobile devices
- Touch-friendly buttons and spacing

### 🔧 Technical

#### Backend
- Python 3.11 with Flask framework
- PostgreSQL database with connection pooling
- Flask-Limiter for rate limiting
- Werkzeug for security features
- QR code generation with python-qrcode
- Jdatetime for Jalali calendar support

#### Frontend
- HTML5 with semantic markup
- CSS3 with CSS variables for theming
- Vanilla JavaScript (no framework dependencies)
- Responsive grid and flexbox layouts
- SVG icons for cross-browser compatibility

#### API
- RESTful JSON API
- Secure session-based authentication
- Login rate limiting (5/min)
- Global rate limits (200/day, 50/hour)

### 📋 Database
- Admins table with superadmin role support
- Servers table with full X-UI panel configuration
- PostgreSQL with secure connection pooling
- Pre-ping health checks for database connections

### 🚀 Deployment Ready
- Environment variable configuration
- PBKDF2 password hashing
- Secure cookie settings
- Failed attempt logging
- Session management with secure flags

### 📱 Responsive Design
- Desktop: 3-column QR code grid
- Tablet (1024px): 2-column grid
- Mobile (768px): 1-column grid with icon-only buttons
- Mobile header with auto-height flex wrapping
- Touch-optimized interface

### 🔒 Security Features Implemented
1. Rate limiting (5 attempts/minute)
2. Secure cookies (HTTPONLY, SAMESITE=Lax)
3. Password hashing (PBKDF2)
4. Failed login logging
5. Environment-based configuration
6. Session timeout (7 days)
7. Admin role-based access
8. Database connection pooling with health checks

### ✅ Quality Assurance
- Tested with Sanaei 3X-UI panels
- Tested with Alireza X-UI panels
- Mobile responsive testing
- Security hardening completed
- Performance optimized with connection pooling

### 📚 Documentation
- Comprehensive README.md
- Technical documentation in replit.md
- API endpoint documentation
- Configuration guide
- Security best practices

### 🐛 Known Limitations
- None at release

### 🙏 Special Thanks

This project was built with careful attention to:
- Enterprise security practices
- User experience across all device sizes
- Performance and reliability
- Clean, maintainable code

---

## Release Schedule

- **1.0.0** - December 1, 2024 (Current)

For feature requests and bug reports, please visit the GitHub issues page.
