# 3x-ui v3 API Reference

> منبع: OpenAPI 3.0.3 زندهٔ پنل (`/{webBasePath}/panel/api/openapi.json`) — تست‌شده روی 3x-ui **v3.3.1**.
> `info.title = "3X-UI Panel API"`, `version = "3.x"`.

**Base:** همهٔ مسیرها نسبت به `webBasePath` پنل‌اند (مثال سرور: `/4FoPrVEMSWkUXilv3D`).
**Auth:** `Authorization: Bearer <token>` (از Settings → Security → API Token) **یا** session cookie (نام کوکی `3x-ui`، از `/login`). همهٔ endpoint‌های `/panel/api/*` هر دو حالت را قبول می‌کنند.
**Response shape:** `{"success": bool, "msg": "...", "obj": ...}`

---

## Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | لاگین با username+password → session cookie. پیش‌نیاز همهٔ فراخوان‌های مبتنی‌بر کوکی. |
| POST | `/logout` | پاک کردن session cookie (برای مرورگر نیازمند CSRF header). |
| GET  | `/csrf-token` | ساخت CSRF token برای session فعلی. کالرهای Bearer نیازی ندارند (middleware برایشان CSRF را short-circuit می‌کند). |
| POST | `/getTwoFactorEnable` | آیا 2FA فعال است؟ (صفحهٔ لاگین برای نمایش فیلد OTP استفاده می‌کند). |

---

## Inbounds `/panel/api/inbounds`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list` | لیست کامل inbound‌ها + `clientStats`. `settings`/`streamSettings`/`sniffing` به‌صورت آبجکت JSON تو در تو برمی‌گردند (نه رشتهٔ escape‌شده). |
| GET | `/list/slim` | مثل `/list` ولی `settings.clients[]` فقط `{email, enable, comment}` و بدون uuid/SubId — برای صفحهٔ لیست. |
| GET | `/options` | picker سبک: `id, remark, tag, protocol, port, tlsFlowCapable, ssMethod`. برای dropdown/attach — بدون settings/streamSettings/clientStats. |
| GET | `/get/{id}` | یک inbound کامل با ID عددی. |
| POST | `/add` | ساخت inbound جدید (payload کامل: protocol, port, settings, streamSettings, sniffing, remark, expiryTime, total, enable). |
| POST | `/update/{id}` | جایگزینی کامل inbound (shape مثل `/add`). روی inbound پر-client سنگین است — برای toggle از `/setEnable` استفاده کن. |
| POST | `/setEnable/{id}` | فقط toggle فیلد enable بدون serialize کل settings (سریع‌تر). |
| POST | `/del/{id}` | حذف inbound + ردیف‌های clientStats مربوط. |
| POST | `/bulkDel` | حذف چند inbound (ترتیبی؛ خطا per-id گزارش می‌شود؛ حداکثر یک restart). |
| POST | `/import` | import inbound از JSON blob — form field: `data`. |
| POST | `/{id}/resetTraffic` | صفر کردن up/down یک inbound (کانترهای per-client دست‌نخورده). |
| POST | `/resetAllTraffics` | صفر کردن up/down همهٔ inbound‌ها (مخرب). |
| POST | `/{id}/delAllClients` | حذف همهٔ client‌های یک inbound (خود inbound می‌ماند؛ مخرب). |
| GET | `/{id}/fallbacks` | لیست fallback rules یک inbound master (VLESS/Trojan TCP-TLS). |
| POST | `/{id}/fallbacks` | جایگزینی کل لیست fallback → restart Xray. |
| POST | `/pushClientTraffics` | دریافت آمار aggregate یک master panel (panel-to-panel، job سینک node). |

---

## Clients `/panel/api/clients`  ← **اصلی در v3**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list` | لیست همهٔ client‌ها + inbound IDs متصل + traffic record. |
| GET | `/list/paged` | filter + sort + pagination سمت سرور؛ ردیف slim (بدون uuid/password/auth/flow/...). page size تا 200. summary روی کل DB. |
| GET | `/get/{email}` | یک client کامل + inbound IDs متصل. |
| POST | `/add` | ساخت client و attach به چند inbound — body: `{client, inboundIds}`. secret‌های per-protocol در صورت حذف، سمت سرور تولید می‌شوند. |
| POST | `/update/{email}` | آپدیت client (replace کامل، نه patch) — روی همهٔ inbound‌های attached اعمال می‌شود. |
| POST | `/del/{email}` | حذف client از همهٔ inbound‌ها (`?keepTraffic=1` برای نگه‌داشتن آمار). |
| POST | `/{email}/attach` | attach client موجود به inbound‌های بیشتر — body JSON. |
| POST | `/{email}/detach` | detach client از inbound‌ها بدون حذف. |
| POST | `/resetTraffic/{email}` | صفر کردن up/down یک client + re-enable در همهٔ inbound‌ها. |
| POST | `/resetAllTraffics` | صفر کردن up/down همهٔ client‌ها (quota/expiry دست‌نخورده). |
| POST | `/updateTraffic/{email}` | تنظیم دستی up/down (برای migration از سیستم accounting خارجی). |
| GET | `/traffic/{email}` | کانترهای traffic یک client. |
| POST | `/delDepleted` | حذف client‌های منقضی/تمام‌شده. |
| POST | `/bulkAdjust` | تغییر expiry/quota چند client — `{addDays, addBytes}` (منفی مجاز؛ unlimited‌ها skip می‌شوند). |
| POST | `/bulkCreate` | ساخت چند client — body: آرایهٔ `[{client, inboundIds}, ...]`. |
| POST | `/bulkDel` | حذف چند client (ترتیبی؛ `keepTraffic=true` برای نگه‌داشتن آمار). |
| POST | `/bulkAttach` | attach چند client به چند inbound. |
| POST | `/bulkDetach` | detach چند client از چند inbound. |
| POST | `/bulkResetTraffic` | صفر کردن traffic چند client. |
| POST | `/ips/{email}` | لیست IP‌های متصل‌شده (آرایهٔ `"ip (timestamp)"`). |
| POST | `/clearIps/{email}` | پاک کردن لیست IP. |
| POST | `/onlines` | email‌های client‌های آنلاین (deduped روی همهٔ node‌ها). |
| POST | `/onlinesByGuid` | آنلاین‌ها گروه‌بندی‌شده بر اساس `panelGuid` نودِ میزبان (برای attribution درست در توپولوژی chain). |
| POST | `/activeInbounds` | inbound tag‌هایی که در پنجرهٔ heartbeat ترافیک داشتند، per node-guid. |
| POST | `/lastOnline` | map: `email → last-seen unix timestamp`. |
| GET | `/subLinks/{subId}` | **همهٔ URL‌های پروتکلی همهٔ کلاینت‌های یک subId** (vless/vmess/trojan/ss/hysteria/hy2) به‌صورت آرایهٔ JSON (بدون base64). نتیجه دقیقاً مثل `/sub/<subId>`. آرایهٔ خالی وقتی subId کلاینت enable ندارد. ← **EVE برای ساب چند-اینباندی از این استفاده می‌کند.** |
| GET | `/links/{email}` | همهٔ URL‌های یک client روی همهٔ inbound‌های attached (مثل دکمهٔ Copy URL پنل). با `externalProxy`، یک URL به‌ازای هر external proxy. |

### Groups `/panel/api/clients/groups`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/groups` | لیست گروه‌ها + تعداد عضو (persisted + derived، مرتب الفبایی). |
| GET | `/groups/{name}/emails` | فقط email‌های یک گروه. |
| POST | `/groups/create` | ساخت گروه خالی (placeholder). |
| POST | `/groups/rename` | تغییر نام گروه (روی client_groups و settings JSON همهٔ inbound‌ها propagate می‌شود). |
| POST | `/groups/delete` | حذف گروه (client‌ها حذف نمی‌شوند، فقط label پاک می‌شود). |
| POST | `/groups/bulkAdd` | افزودن چند client به گروه (auto-create اگر گروه نباشد). |
| POST | `/groups/bulkRemove` | پاک کردن label گروه از چند client. |

---

## Server `/panel/api/server`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | snapshot لحظه‌ای: CPU/RAM/swap/disk/network IO/load/connections/Xray state (cache 2s). |
| GET | `/history/{metric}/{bucket}` | time-series یک metric — آرایهٔ `{t, v}` (آخرین ~۶ ساعت). |
| GET | `/cpuHistory/{bucket}` | (legacy) تاریخچهٔ CPU — به‌جایش از `/history/cpu/{bucket}`. |
| GET | `/xrayMetricsState` | وضعیت metrics block در Xray config + snapshot expvar. |
| GET | `/xrayMetricsHistory/{metric}/{bucket}` | time-series یک Xray runtime metric. |
| GET | `/xrayObservatory` | آخرین snapshot observatory (latency/health/last-probe per outbound). |
| GET | `/xrayObservatoryHistory/{tag}/{bucket}` | time-series نتایج probe یک outbound tag. |
| GET | `/getConfigJson` | Xray config در حال اجرا (assembled). |
| GET | `/getXrayVersion` | لیست نسخه‌های Xray قابل نصب. |
| GET | `/getPanelUpdateInfo` | آیا نسخهٔ جدیدتر روی GitHub هست؟ |
| GET | `/getDb` | دانلود فایل SQLite DB (backup). |
| GET | `/getMigration` | دانلود migration file (cross-engine). |
| GET | `/getNewUUID` | UUID v4 جدید. |
| GET | `/getNewX25519Cert` | keypair جدید X25519 برای Reality. |
| GET | `/getNewmldsa65` | ML-DSA-65 keypair (post-quantum signature) → `{privateKey, publicKey, seed}`. |
| GET | `/getNewmlkem768` | ML-KEM-768 keypair (post-quantum KEM) → `{clientKey, serverKey}`. |
| GET | `/getNewVlessEnc` | VLESS encryption auth options (آرایهٔ `auths`). |
| POST | `/getNewEchCert` | ECH (Encrypted Client Hello) keypair برای یک SNI. |
| GET | `/getWebCertFiles` | مسیر cert/key وب پنل (central روی node صدا می‌زند). |
| GET | `/clientIps` | کل جدول `inbound_client_ips` (sync IP بین cluster). |
| POST | `/clientIps` | ارسال timestamp‌های IP فعال برای merge. |
| GET | `/descendants` | خلاصهٔ read-only نودهای زیرمجموعه (chained topology). |
| POST | `/stopXrayService` | توقف Xray. |
| POST | `/restartXrayService` | reload Xray با config فعلی. |
| POST | `/installXray/{version}` | نصب نسخهٔ Xray (`latest` قبول است). |
| POST | `/updatePanel` | self-update پنل (restart می‌شود). |
| POST | `/updateGeofile` | refresh GeoIP/GeoSite (body می‌تواند `fileName` داشته باشد). |
| POST | `/updateGeofile/{fileName}` | refresh یک Geo file (مثل geoip.dat). |
| POST | `/logs/{count}` | آخرین N خط log پنل. |
| POST | `/xraylogs/{count}` | آخرین N خط log Xray. |
| POST | `/importDB` | restore DB از فایل SQLite (multipart field `db`) — restart (مخرب). |

---

## Nodes `/panel/api/nodes`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list` | لیست node‌ها + connection details + health + last heartbeat. |
| GET | `/get/{id}` | یک node. |
| GET | `/webCert/{id}` | cert/key وب یک node (proxy‌شده) — برای "Set Cert from Panel". |
| GET | `/history/{id}/{metric}/{bucket}` | time-series یک metric یک node. |
| POST | `/add` | ثبت node — `{url, apiToken, remark, allowPrivateAddress?}`. |
| POST | `/update/{id}` | آپدیت connection details node. |
| POST | `/del/{id}` | حذف node (inbound‌های bound auto-migrate نمی‌شوند). |
| POST | `/setEnable/{id}` | pause/resume سینک. |
| POST | `/test` | probe بدون save (body = connection details). |
| POST | `/probe/{id}` | probe node موجود و آپدیت health. |
| POST | `/certFingerprint` | SHA-256 (base64) leaf cert یک node — برای pin کردن self-signed. |
| POST | `/inbounds` | لیست inbound‌های remote یک node (با connection details ذخیره‌نشده) برای import گزینشی. |
| POST | `/updatePanel` | self-update روی node‌های enable/online. |

---

## Settings `/panel/api/setting`

> ⚠️ در v3.3.1 مسیر `/panel/api/setting/*` است (نه `/panel/setting/*`).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/all` | همهٔ تنظیمات پنل (web/telegram/subscription/security/ldap). |
| POST | `/defaultSettings` | تنظیمات پیش‌فرض محاسبه‌شده بر اساس host. |
| POST | `/update` | ذخیرهٔ همهٔ تنظیمات (shape مثل `/all`؛ مقادیر نامعتبر rejected). |
| POST | `/updateUser` | تغییر username/password ادمین (نیازمند credential فعلی). |
| POST | `/restartPanel` | restart کل process پنل (~۵-۱۰ ثانیه down). |
| GET | `/getDefaultJsonConfig` | template پیش‌فرض Xray config این نسخه. |

### API Tokens `/panel/api/setting/apiTokens`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/apiTokens` | لیست token‌ها (value هرگز برنمی‌گردد — فقط metadata). |
| POST | `/apiTokens/create` | ساخت token (نام unique، 1-64 کاراکتر؛ plaintext فقط همین یک بار، hashed ذخیره می‌شود). |
| POST | `/apiTokens/delete/{id}` | حذف token. |
| POST | `/apiTokens/setEnabled/{id}` | enable/disable token. |

---

## Xray Settings `/panel/api/xray`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/` | config template (رشتهٔ JSON) + inbound tag‌ها + client reverse tag‌ها + outbound test URL. |
| POST | `/update` | ذخیرهٔ Xray config template و اختیاری outbound test URL (form fields). |
| GET | `/getDefaultJsonConfig` | default Xray config (مثل `/setting/getDefaultJsonConfig`). |
| GET | `/getOutboundsTraffic` | آمار traffic هر outbound (up/down/total). |
| GET | `/getXrayResult` | آخرین stdout/stderr پروسهٔ Xray. |
| POST | `/resetOutboundsTraffic` | reset traffic یک outbound by tag. |
| POST | `/testOutbound` | test یک outbound config. |
| POST | `/testOutbounds` | test batch (تا ۵۰) در یک instance موقت — نتایج با delay/HTTP status/timing. |
| POST | `/routeTest` | router کدام outbound را برای یک اتصال فرضی انتخاب می‌کند (بدون ارسال traffic). |
| POST | `/balancerStatus` | وضعیت زندهٔ balancer‌های routing (override + targets). |
| POST | `/balancerOverride` | اجبار balancer به یک outbound مشخص (live، بدون restart). |
| POST | `/warp/{action}` | مدیریت Cloudflare Warp. |
| POST | `/nord/{action}` | مدیریت NordVPN. |
| GET | `/outbound-subs` | لیست outbound subscription‌ها (URL‌های remote که outbound می‌دهند). |
| POST | `/outbound-subs` | ساخت outbound subscription (fetch + parse + merge افزایشی). |
| POST | `/outbound-subs/parse` | preview یک URL بدون persist. |
| POST | `/outbound-subs/{id}` | آپدیت یک outbound subscription. |
| DELETE | `/outbound-subs/{id}` | حذف. |
| POST | `/outbound-subs/{id}/del` | حذف (alias POST برای axios). |
| POST | `/outbound-subs/{id}/move` | جابه‌جایی priority (up/down). |
| POST | `/outbound-subs/{id}/refresh` | re-fetch فوری + reload Xray. |

---

## Backup

| Method | Path | Description |
|--------|------|-------------|
| POST | `/panel/api/backuptotgbot` | ارسال DB backup تازه به همهٔ chat‌های ادمین تلگرام (بدون body/param). |

---

## Subscription Server (پورت جداگانه، default: 10882)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{subPath}{subid}` | لینک‌های base64 همهٔ client‌های enable یک subId. با `Accept: text/html` یا `?html=1` صفحهٔ info رندر می‌شود. default path: `/sub/`. |
| GET | `/{jsonPath}{subid}` | آرایهٔ JSON کانفیگ‌ها (per enabled client). فقط اگر JSON sub فعال باشد. default: `/json/`. |
| GET | `/{clashPath}{subid}` | YAML سازگار با Clash/Mihomo + routing rules. فقط اگر Clash sub فعال باشد. default: `/clash/`. |

> **معادل API:** برای گرفتن همان مجموعهٔ لینک‌ها روی **پورت اصلی API** (مستقل از سرور ساب جداگانه)، از `GET /panel/api/clients/subLinks/{subId}` استفاده کن.

---

## WebSocket `/ws`

فقط با session cookie (Bearer پشتیبانی نمی‌شود). موفقیت → `101 Switching Protocols`. سرور پیام‌های JSON push می‌کند:

| `type` | Description |
|--------|-------------|
| `invalidate` | UI باید resource را دوباره fetch کند (وقتی ادمین دیگری داده را تغییر می‌دهد). |
| `notification` | toast داخل پنل (stop/restart Xray، import DB، restart پنل، ...). |
| `status` | snapshot سلامت هر ۲ ثانیه (مثل `GET /panel/api/server/status`). |
| `xrayState` | تغییر state پروسهٔ Xray (start/stop/error). |

---

## نکات مهم v3

- **Client اول‌درجه:** در v3 client‌ها مستقل از inbound مدیریت می‌شوند — endpoint‌های قدیمی `updateClient`/`delClient`/`resetClientTraffic` روی `/inbounds` حذف شده‌اند و 404 می‌دهند.
- **Update client:** `POST /panel/api/clients/update/{email}` — body کامل client (replace، نه patch).
- **Add client:** `POST /panel/api/clients/add` — body: `{client: {...}, inboundIds: [1,2,3]}`.
- **Attach/Detach:** برای تغییر inbound assignment بدون حذف client.
- **چند-اینباندی و ساب:** یک `subId` می‌تواند به چند inbound وصل باشد. `/sub/<subId>` (و معادل API آن `/clients/subLinks/{subId}`) همهٔ آن‌ها را یکجا برمی‌گرداند. برای ساخت لینک‌ها مطمئن باش **همهٔ** اینباندهای آن subId را جمع کرده‌ای، نه فقط اولی.
- **Bearer token:** از Settings → Security → API Token — هرگز expire نمی‌شود.
- **Settings path:** در v3.3.1 زیر `/panel/api/setting/*` است (نه `/panel/setting/*`).
