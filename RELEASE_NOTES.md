# Eve - Xui Manager v2.3.2

## [2.3.2] - 2026-06-20

English:
- Feature: **Per-reseller WhatsApp automation permission** — new "WhatsApp Automation Enabled" switch in each reseller's user settings (default OFF). The system will not message a reseller's clients from the owner's WhatsApp number unless the reseller is explicitly opted in
- Scope: both the background near-depletion scanner and the automatic post-renewal WhatsApp message now skip reseller-owned accounts whose owner hasn't enabled automation
- Owner/admin/superadmin accounts are always eligible (unchanged)

فارسی:
- قابلیت: **پرمیشن اتوماسیون واتساپ به‌ازای هر رسلر** — سوییچ جدید «اتوماسیون واتساپ فعال» در تنظیمات هر رسلر (پیش‌فرض خاموش). تا وقتی این گزینه روشن نشده باشد، سیستم با شماره‌ی owner به کلاینت‌های آن رسلر پیام نمی‌دهد
- دامنه: هم اسکن خودکار near-depletion و هم ارسال خودکار بعد از تمدید، اکانت‌های متعلق به رسلرِ بدون این مجوز را نادیده می‌گیرند
- اکانت‌های owner/ادمین/سوپرادمین همیشه شامل اتوماسیون هستند (بدون تغییر)

## [2.3.1] - 2026-06-20

English:
- Feature: **Reseller "Free" permission** — the Free toggle for new purchases, renewals, and traffic resets is now hidden from resellers unless explicitly granted. Enable the new "Allow Free Creation" switch in the reseller's user settings to show it
- Security: server-side enforcement on all three free-action endpoints — resellers without the permission are rejected with HTTP 403 even if the client is tampered with
- Admins and superadmins are unaffected (they don't consume credit)

فارسی:
- قابلیت: **پرمیشن «رایگان» برای رسلر** — تاگل Free هنگام ساخت، تمدید و ریست ترافیک تا وقتی در تنظیمات یوزر رسلر فعال نشده باشد نمایش داده نمی‌شود. با روشن کردن سوییچ «مجاز به ساخت/تمدید رایگان» در تنظیمات کاربر، این گزینه برایش لود می‌شود
- امنیت: اعمال محدودیت سمت سرور روی هر سه اندپوینت — رسلر بدون این پرمیشن حتی با دستکاری سمت کلاینت با خطای ۴۰۳ رد می‌شود
- ادمین و سوپرادمین تحت تأثیر نیستند (اعتبار خرج نمی‌کنند)

## [2.3.0] - 2026-06-20

English:
- Feature: **WhatsApp Bot (OpenWA)** — integrate Eve with OpenWA self-hosted gateway as an alternative to Baileys; send WhatsApp messages through your own local server
- Feature: **Warm-up mode** — linear ramp-up of the daily WhatsApp send cap over N configurable days to avoid ban risk on new sessions
- Feature: **Near-depletion bot** — background scanner (every 30 min) automatically messages clients whose subscription volume or time is running low; configurable thresholds, cooldown period, and database deduplication
- Feature: **WhatsApp Bot Templates** — dedicated templates for Created, Renew, Ended, and Info events, separate from SMS templates with their own placeholders
- Feature: **Pace gate** — optional minimum gap + random jitter between WhatsApp sends to mimic human behavior (disabled by default)
- Feature: **Ban-risk warning** — prominent warning banner when OpenWA provider is selected with safe-usage recommendations
- Feature: **Monitor zero-usage badge** — idle clients shown with a distinct chip; Royalty Information template sent directly from the monitor table; per-client SMS/WA send counter visible in the row
- Feature: **WhatsApp/SMS template variants** — dedicated Created and Renew message templates for WhatsApp and SMS with test-send buttons
- Feature: **Conditional gift blocks** — `{if_gift}…{/if_gift}` and `{gift_volume}` placeholders available in all template editors
- Feature: **Announcement media upload** — inline image/video upload directly in the announcement message editor; new popup modal announcement type with custom button label
- Feature: **Backup Database button** — added to server management cards on the Servers page
- Feature: **Reseller owner badges** — multi-select owner filter for admin on the Packages page
- Feature: **Subscription history** — compact inline renewal line, paginated table (10/page), renewal days marked
- Feature: **Persian/Arabic digit search** — search box converts Persian/Arabic digits to ASCII automatically
- Feature: **"Why?" error modal** — server cards explain fetch errors in plain language
- Feature: **v3 Last User** — shows recent clients only for checked inbounds, refreshed on toggle, deduplicated
- Feature: **Volume stats button** — added to v3 server cards for quick traffic overview
- Improvement: **Dashboard lazy rows** — incremental render in chunks so the dashboard is interactive before all data arrives
- Improvement: **Write-through cache** — edits and renewals update the in-memory cache instantly across all panel types
- Improvement: **Upload progress UI** — real-time progress bar during backup restore; 512 MB upload limit
- Improvement: **X-Accel streaming** — large backup downloads stream through Nginx to avoid Gunicorn timeout
- Fix: **3x-ui v3.3.1 CSRF** — Eve now fetches `X-CSRF-Token` before login; fully backward compatible with older panels
- Fix: **http→https self-heal** — server saved with `http://` retried over `https://` when the panel is SSL-only
- Fix: **`{dashboard_link}` & `{sub_link}`** — placeholders now correctly populated in monitor alert messages
- Fix: **Spaced email handling** — emails with spaces renamed on panel before any v3 operation; search and dedup handle them correctly
- Fix: **Emoji on iOS** — emoji in messages preserved correctly on iOS devices; SSL auto-applied after cert upload
- Fix: **SSL nginx auto-reload** — renewal reloads Nginx automatically; fixed 500 error on root-owned cert destination
- Fix: **Royalty dedup** — idle list deduped by email-per-server; synchronous scan replaces fragile background job
- Fix: **Shadowsocks** — non-v3 update/delete operations restored; v3 last-user from client list fixed
- Fix: **Pricing** — dynamic tier price no longer overwritten by package loader on re-open
- Fix: **Ownership anchor** — client owner anchored to panel UUID so server/inbound edits don't lose ownership
- Fix: **Server list stale** — server list refreshes correctly after editing a server

Persian (فارسی):
- ویژگی: **واتس‌اپ بات (OpenWA)** — اتصال Eve به گیت‌وی خود-میزبان OpenWA به‌عنوان جایگزین Baileys؛ ارسال پیام واتس‌اپ از طریق سرور لوکال خودتان
- ویژگی: **حالت Warm-up** — افزایش تدریجی سقف ارسال روزانه واتس‌اپ طی N روز قابل تنظیم برای جلوگیری از بن شدن شماره جدید
- ویژگی: **بات اعلان اتمام حجم/زمان** — اسکنر پس‌زمینه (هر ۳۰ دقیقه) که به‌صورت خودکار به کاربرانی که حجم یا زمان اشتراک‌شان رو به اتمام است پیام می‌دهد؛ آستانه، فاصله زمانی، و جلوگیری از ارسال تکراری قابل تنظیم است
- ویژگی: **قالب‌های بات واتس‌اپ** — قالب‌های اختصاصی برای رویدادهای ساخت، تمدید، پایان، و اطلاع‌رسانی جداگانه از قالب‌های SMS
- ویژگی: **Pace Gate** — حداقل فاصله اختیاری + تأخیر تصادفی بین ارسال‌های واتس‌اپ برای شبیه‌سازی رفتار انسانی (پیش‌فرض: غیرفعال)
- ویژگی: **هشدار ریسک بن** — بنر هشدار برجسته هنگام انتخاب OpenWA با توصیه‌های استفاده ایمن
- ویژگی: **نشان بدون مصرف در مانیتور** — کاربران بی‌فعالیت با چیپ مجزا نمایش داده می‌شوند؛ قالب Royalty مستقیم از جدول مانیتور ارسال می‌شود؛ شمارنده ارسال SMS/WA در هر ردیف
- ویژگی: **قالب‌های مجزا واتس‌اپ/SMS** — قالب‌های اختصاصی ساخت و تمدید برای واتس‌اپ و SMS با دکمه تست ارسال
- ویژگی: **بلوک‌های شرطی هدیه** — پلیس‌هولدرهای `{if_gift}…{/if_gift}` و `{gift_volume}` در همه ویرایشگرهای قالب
- ویژگی: **آپلود رسانه در اعلان‌ها** — آپلود تصویر/ویدیو مستقیم در ویرایشگر پیام اعلان؛ نوع اعلان پاپ‌آپ مودال با برچسب دکمه سفارشی
- ویژگی: **دکمه بکاپ دیتابیس** — اضافه شده به کارت‌های مدیریت سرور در صفحه Servers
- ویژگی: **نشان مالک ریسلر** — فیلتر چندانتخابی مالک برای ادمین در صفحه Packages
- ویژگی: **تاریخچه اشتراک** — خط تمدید فشرده، جدول صفحه‌بندی‌شده (۱۰ ردیف)، روزهای تمدید علامت‌گذاری شده
- ویژگی: **جستجوی عدد فارسی/عربی** — باکس جستجو اعداد فارسی/عربی را خودکار به ASCII تبدیل می‌کند
- ویژگی: **مودال "چرا؟"** — کارت سرورها خطاهای fetch را به زبان ساده توضیح می‌دهند
- ویژگی: **آخرین کاربر v3** — فقط برای inbound های انتخاب‌شده نمایش داده می‌شود، با تغییر toggle به‌روزرسانی می‌شود
- ویژگی: **دکمه آمار حجم** — اضافه شده به کارت‌های سرور v3
- بهبود: **رندر تدریجی داشبورد** — ردیف‌ها به‌صورت دسته‌ای mount می‌شوند تا داشبورد قبل از لود کامل داده‌ها قابل استفاده باشد
- بهبود: **کش نوشتاری** — ویرایش‌ها و تمدیدها فوراً کش حافظه را به‌روز می‌کنند برای همه انواع پنل
- بهبود: **نوار پیشرفت آپلود** — پیشرفت واقعی هنگام آپلود بکاپ؛ سقف آپلود ۵۱۲ مگابایت
- بهبود: **Streaming از طریق Nginx** — دانلود بکاپ‌های بزرگ بدون timeout از طریق X-Accel-Redirect
- رفع: **CSRF در v3.3.1** — Eve قبل از لاگین `X-CSRF-Token` می‌گیرد؛ کاملاً backward compatible
- رفع: **خود-درمانی http→https** — سرور ذخیره‌شده با `http://` روی `https://` retry می‌شود
- رفع: **`{dashboard_link}` و `{sub_link}`** — این پلیس‌هولدرها اکنون در پیام‌های اعلان مانیتور درست پر می‌شوند
- رفع: **ایمیل با فاصله** — ایمیل‌های دارای فاصله قبل از عملیات v3 روی پنل rename می‌شوند
- رفع: **ایموجی در iOS** — ایموجی در پیام‌ها روی iOS درست حفظ می‌شود؛ SSL بعد از آپلود خودکار اعمال می‌شود
- رفع: **بارگذاری مجدد Nginx پس از SSL** — تمدید SSL به‌صورت خودکار Nginx را reload می‌کند
- رفع: **Shadowsocks** — عملیات update/delete برای پروتکل Shadowsocks غیر v3 بازیابی شد
- رفع: **مالکیت کاربر** — مالک به UUID پنل وابسته شد تا ویرایش سرور/inbound مالکیت را از دست ندهد

---

# Eve - Xui Manager v1.9.7

## [1.9.7] - 2026-05-19

English:
- Feature: File Manager in Applications section — upload installers (APK, EXE, DMG, DEB, RPM, ZIP) and tutorial videos (MP4, WebM, MKV) directly from the Subscription Page Manager with drag-and-drop support, real-time progress bar, category filter tabs, and secure server-side validation
- Feature: Browse button on Direct Download Link and Video Tutorial Link fields — pick files from the server or upload new ones without leaving the form
- Improvement: QR code modal now opens instantly; all QR codes load in parallel instead of sequentially — eliminates the long wait before the modal appears
- Fix: Mobile client card layout — removed double border line between username and status rows, improved spacing (more breathing room between cards and rows), action buttons are now square (36×36 px)
- Fix: Email, client name, and comment fields now wrap text on mobile instead of truncating — long usernames are always fully visible
- Fix: Last User label in Purchase New Service moved above the field (not shown inline inside the input) so long usernames display fully with word-wrap
- Fix: VPN user-agent detection — corrected `napsternetv` token (was misspelled `napstarnet`), added new app tokens: `karing`, `v2raytun`, `mahsa`, `npv`, `flclash`, `furious`, `clash-verge`, `clashverge`, `v2rayx`, `musedaq`, `v2rayn`, `v2raya`, `nekoray`, `qv2ray`
- Fix: Phone number extraction — spaced numbers like `0912 833 4643` now match correctly; `1097` or similar account names no longer cause false phone matches (bare `98` prefix rejected; only `+98` accepted); comment field now checked as fallback if no number found in email/name

Persian (فارسی):
- ویژگی: مدیر فایل در بخش Applications — آپلود فایل‌های نصبی (APK، EXE، DMG، DEB، RPM، ZIP) و ویدیوهای آموزشی (MP4، WebM، MKV) مستقیم از Subscription Page Manager با پشتیبانی از Drag & Drop، نوار پیشرفت، فیلتر بر اساس دسته‌بندی، و اعتبارسنجی امن سمت سرور
- ویژگی: دکمه Browse روی فیلدهای Direct Download Link و Video Tutorial Link — انتخاب از فایل‌های موجود یا آپلود جدید بدون خروج از فرم
- بهبود: مودال QR Code اکنون فوراً باز می‌شود؛ تمام کدهای QR به‌صورت موازی بارگذاری می‌شوند — انتظار طولانی قبل از نمایش مودال حذف شد
- رفع: لیوات کارت کلاینت در موبایل — خط دوتایی اضافی بین ردیف نام کاربر و وضعیت برطرف شد، فاصله‌گذاری بهبود یافت، دکمه‌های عملیات مربعی (۳۶×۳۶) شدند
- رفع: فیلدهای ایمیل، نام کلاینت، و کامنت در موبایل اکنون wrap می‌شوند به جای truncate — نام‌های کاربری بلند همیشه کامل دیده می‌شوند
- رفع: لیبل Last User در Purchase New Service بالای فیلد نمایش داده می‌شود (نه داخل input) تا نام‌های بلند با word-wrap کامل دیده شوند
- رفع: تشخیص User-Agent برنامه‌های VPN — توکن `napsternetv` اصلاح شد (قبلاً `napstarnet` بود)، توکن‌های جدید اضافه شدند: karing، v2raytun، mahsa، npv، flclash، furious، clash-verge، v2rayx، و سایرین
- رفع: استخراج شماره موبایل — اعداد فاصله‌دار مثل `0912 833 4643` اکنون شناسایی می‌شوند؛ نام‌هایی مثل `1097` دیگر false match نمی‌دهند (پیشوند `98` بدون `+` رد می‌شود)؛ فیلد comment نیز به عنوان fallback بررسی می‌شود

Security notes:
- File uploads validated by extension whitelist + MIME-independent checks
- All uploaded filenames prefixed with UUID to prevent enumeration
- Path traversal prevented via os.path.realpath comparison
- Upload endpoint restricted to superadmin role only

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
