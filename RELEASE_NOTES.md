# Eve - Xui Manager v1.9.1

## [1.9.1] - 2026-05-12

English:
- Feature: Enhanced dashboard showing real-time panel info - panel type badges, Xray version, X-UI version, and server state indicators
- Feature: New `/api/servers/{id}/panel-info` endpoint for quick server status verification after addition
- Feature: Settings overview page with system health: uptime, last backups, database type, version info, SSL certificate details
- Improvement: Added Werkzeug ProxyFix middleware for proper Nginx SSL termination support
- Improvement: Better error states for unreachable servers with visual indicators
- Fix: Server list properly refreshes after adding new server
- Tweak: Improved XSS protection with HTML escaping in templates

Notes:
- All new features use existing @login_required authentication
- ProxyFix supports standard Nginx reverse proxy configurations
- Server panel info can be refreshed on-demand from dashboard

# Eve - Xui Manager v1.9.0

## [1.9.0] - 2026-05-12

English:
- Feature: Multi-version X-UI panel compatibility - auto-detect and support both JSON-body (v3.0.0+) and form-encoded login methods for better cross-version compatibility
- Feature: Self-signed SSL certificate support in setup with improved validation
- Improvement: Extended panel connection timeout from 3s to 8s for more reliable authentication across diverse deployments
- Improvement: SSL session verification consistency across all request types and redirects
- Fix: SSL settings validation now checks file existence and read permissions before saving
- Fix: Prevented partial cert/key configuration saves with better error handling
- Tweak: Suppressed urllib3 SSL warnings for cleaner logs

Notes:
- Panel connection logic is more resilient to different deployment scenarios
- SSL configuration validation prevents common setup mistakes upfront
- All changes maintain backward compatibility

# Eve - Xui Manager v1.5.1

## [1.5.1] - 2025-12-18

English:
- Fix: Background refresh jobs run inside Flask `app_context`, fixing cases where background refreshes failed to update cache (renew/reset/actions now reflect in UI without manual refresh).
- Fix: `setup.sh` and migration scripts updated so Postgres configuration persists across updates (no accidental fallback to SQLite). `migrations.py` now skips SQLite-only checks when `DATABASE_URL` points to Postgres.
- Improvement: Refresh system made non-blocking with server-scoped jobs + polling; frontend uses cached-first rendering and performs lightweight server refreshes after client actions for faster UX.
- Fix: Dashboard aggregate counters restored (`unlimited_expiry_clients`, `unlimited_volume_clients`, `not_started_clients`) so summary metrics show correctly.
- Tweak: Reduced panel login timeout during session creation to avoid long blocking refreshes.

Notes:
- These changes improve update reliability (Postgres), background job correctness, and dashboard real-time UX. See commits for details.

# Eve - Xui Manager v1.5.0

## [1.5.0] - 2025-12-16

Persian (فارسی):
- نسخه 1.5.0 شامل بهبودهای ظاهری و تجربه کاربری صفحه "Finance" است:
	- بازطراحی بخش Summary به صورت یک "feed" قابل بازشدن (lazy-load) برای کاهش بار اولیه و بهبود نمایش در موبایل.
	- در نمایش‌های میانی (≤1100px) مقادیر Overview دیگر با نقطهٔ انتهایی (ellipsis) بریده نمی‌شوند؛ اکنون خط‌شکنی فعال و کلمه‌شکنی (`word-break`) انجام می‌شود تا از همپوشانی متن جلوگیری شود.
	- شبکهٔ Overview در تبلت‌ها به دو ستون تبدیل شده (≤900px) تا فضای هر آیتم بیشتر و خواناتر شود.
	- نمای کارت‌گونهٔ جدول تراکنش‌ها اکنون از عرض ≤1024px فعال می‌شود (قبلاً برای موبایل محدود بود) و مقدار `Amount` در این نما هم‌راستا شده تا از افتادن به خط پایین جلوگیری شود.
	- شبکهٔ فیلترها در صفحهٔ پرداخت‌ها در ≤1024px به دو ستون منتقل شده تا فیلدها قابل دسترس و مرتب بمانند.
	- رنگ‌ها و استایلِ badge های نوع تراکنش یکپارچه شدند تا خوانایی بهتر شود.
	- انتخابگر ماه (Jalali) در Summary به‌صورت درون بدنهٔ Summary قرار گرفته و داده‌های ماه‌ها هنگام بازکردن Summary بارگذاری می‌شوند (lazy-load).
	- چند اصلاح JavaScript برای امن‌تر کردن رندر، برطرف‌کردن برش‌های طولانی، و مرتب‌سازی/فیلتر صحیح داده‌ها انجام شد.
	- فایل قدیمی تمپلیت `templates/financeold.html` حذف شد تا از سردرگمی جلوگیری شود.
	- نسخهٔ برنامه به `v1.5.0` ارتقا یافت.

English:
- v1.5.0 focuses on responsive and UX improvements for the Finance area (changes since v1.4.2):
	- Summary redesigned as a collapsible feed and lazy-loaded when opened to reduce initial load and improve mobile UX.
	- Overview numeric values no longer truncate with ellipsis on mid widths (≤1100px); they now wrap and use word-break to prevent text overlap.
	- Overview grid switches to two columns on narrower tablets (≤900px) to give each metric more space and improve readability.
	- Payments table now switches to a card (mobile) view up to 1024px (previously only on small screens); `Amount` is kept aligned to avoid line wrapping.
	- Filters grid is forced into two columns at ≤1024px for a cleaner, more usable filter layout.
	- Transaction type badges got consistent styling and color tokens for clearer visual identification.
	- The Jalali month picker for the summary is loaded inside the Summary body and months/data are lazy-loaded on expand.
	- Several JS improvements: safer rendering of dynamic content, better truncation handling, ordering/limits applied correctly in overview rendering.
	- Removed legacy template `templates/financeold.html` to avoid confusion.
	- Application version bumped to `v1.5.0`.

Notes:
- These changes are primarily client-side (templates, CSS, and frontend JS) and aim to improve usability at tablet and laptop breakpoints (around 900–1100px and 1024px).

## 🐛 Bug Fixes & Improvements (previous)
- **Reseller Visibility**: Fixed issue where clients were hidden from resellers due to missing inbound IDs (implemented loose matching).
- **Traffic Formatting**: Improved traffic display to dynamically show KB/MB/GB/TB units.
- **UI Alignment**: Fixed action button alignment on desktop (right-aligned) and mobile (left-aligned).
- **Server List**: Fixed bug where server list in modals would be empty after status updates.
- **Search Autofill**: Implemented fix to prevent browser autofill on the search input.

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
