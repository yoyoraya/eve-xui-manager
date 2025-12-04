# Eve - Xui Manager

## Overview
Eve is a professional web-based monitoring dashboard designed for multiple X-UI VPN panels. It offers enterprise-grade security, secure authentication, and comprehensive statistics. The platform supports an unlimited number of X-UI servers (both Sanaei 3X-UI and Alireza X-UI variants) and includes a robust reseller management system. Its main purpose is to provide a centralized, secure, and efficient solution for managing VPN services, targeting businesses and individuals who require scalable and secure VPN panel oversight.

## User Preferences
- Dark theme
- English-only interface (LTR)
- Clean, modern design
- Professional authentication
- Enterprise security
- Reseller system for multi-level management

## System Architecture

### UI/UX Decisions
The system features a professional login page, responsive sidebar navigation, a 3-column QR Code grid (adaptable to 2-column on tablet and 1-column on mobile), and color-coded expiry badges. The design emphasizes a dark theme, clean aesthetics, and mobile-friendliness. Silent auto-refresh for data ensures a non-blocking user experience, while smart manual refresh provides immediate updates with a button spinner.

### Technical Implementations
- **Authentication & Security**: Professional login with rate limiting (5 attempts/minute per IP), secure session management (HTTPONLY, SAMESITE), password hashing (PBKDF2), environment-based default passwords, and failed login logging.
- **Multi-Server Support**: Ability to add unlimited X-UI panels with auto-detection of panel type (Sanaei/Alireza). Features per-server session handling and customizable subscription/JSON paths and configurable subscription ports.
- **Dashboard Features**: Statistics overview (servers, inbounds, clients, traffic), global search for clients by email across all servers, and real-time traffic display.
- **Client Management**: Enable/disable clients, reset client traffic, renew clients with "Start after first use" option, and generation of three types of QR codes per client (Subscription, Subscription JSON, Direct Link).
- **Expiry Display**: Shows remaining days (color-coded) and supports "Start after first use" with Jalali calendar integration.
- **Reseller System**: Three-tier role system (superadmin, admin, reseller), credit system with role-based deduction, server access control per reseller, and client ownership tracking. Resellers only see clients and servers they are authorized for.

### System Design Choices
- **Backend**: Python 3.11 with Flask.
- **Database**: PostgreSQL for robust data storage.
- **Frontend**: HTML5, CSS3, and Vanilla JavaScript for a lightweight and responsive interface.
- **Security**: Utilizes Werkzeug for security utilities and Flask-Limiter for rate limiting.
- **Styling**: Custom CSS for a dark theme.
- **Database Schema**:
    - **Admins Table**: Stores admin credentials, roles (superadmin, admin, reseller), credit limits, and allowed servers.
    - **Servers Table**: Stores details for each X-UI panel, including connection info and custom paths.
    - **ClientOwnership Table**: Tracks which reseller owns which client, facilitating the reseller system.

### API Endpoints
- **Authentication**: `/login`, `/logout`
- **Page Endpoints**: `/`, `/servers`, `/admins`
- **Admin Management API**: CRUD operations for admins.
- **Server Management API**: CRUD operations for servers, including connection testing.
- **Reseller Client Assignment API**: `/api/assign-client` for assigning clients to resellers.
- **Data & Client Management API**: Refresh data, toggle, reset, and renew client services, and QR code generation.

## External Dependencies
- **PostgreSQL**: Used as the primary database for storing all application data.
- **X-UI Panels**: Integrates with both Sanaei 3X-UI and Alireza X-UI for VPN server management.
- **Werkzeug**: Used for security, specifically password hashing.
- **Flask-Limiter**: Implements rate limiting for brute-force protection.
## FINAL CHECKPOINT - COMPLETE RESELLER SYSTEM ✅

**December 04, 2025 - All 5 Phases Completed**

### What Was Built:

**Phase 1: Database Schema** ✅
- Admin model with role, credit, allowed_servers fields
- ClientOwnership table for client-reseller associations

**Phase 2: Backend APIs & Filtering** ✅
- Smart role-based filtering in all endpoints
- /api/assign-client for client ownership
- /api/servers/{id}/test for connection testing

**Phase 3: Frontend UI - Admin & Dashboard** ✅
- admins.html: Full CRUD with role/credit/server management
- dashboard.html: Credit badge + Assign Owner button
- Menu visibility fixed for superadmin detection

**Phase 4: Frontend Security - Servers Page** ✅
- Add/Edit/Delete buttons hidden for non-superadmins
- Test Connection button visible to all roles
- IS_SUPERADMIN properly passed and used

**Phase 5: Polish - Sidebar Enhancement** ✅
- Role name displayed on all pages (Reseller/Admin/SuperAdmin)
- Credit balance shown in sidebar for resellers
- Consistent UI across entire application

### System Status:
🟢 **RUNNING** - All features tested and working
🔒 **SECURE** - Rate limiting, session management, password hashing
📊 **COMPLETE** - 5 phases, 3 role levels, full reseller system

### Ready for Deployment:
✅ All code clean and organized
✅ Database schema complete
✅ APIs fully implemented
✅ Frontend secured and polished
✅ Session management active

**Production Status: READY TO DEPLOY** 🚀

---

## PHASE 1 - BILLING & ACCOUNTING SYSTEM ✅

**December 04, 2025 - Infrastructure Complete**

### Database Models Added:
- **Package**: Predefined packages (days, volume, price)
- **SystemConfig**: Base pricing configuration (cost_per_gb, cost_per_day)
- **Transaction**: Complete transaction ledger for wallet tracking
- **Admin.transactions**: Relationship to track all user transactions

### API Endpoints Added:
1. **GET /api/packages** - List enabled packages (for user selection)
2. **POST /admin/packages** - Create new package (superadmin only)
3. **POST /admin/config** - Update system pricing configuration (superadmin only)
4. **POST /admin/charge** - Manually add credit to user (superadmin only)
5. **GET /api/transactions** - Get transaction history (role-filtered)

### Default Configuration Seeded:
- `cost_per_gb`: 2000 تومان
- `cost_per_day`: 500 تومان

### System Status:
🟢 Phase 1 complete - All 4 models created, 5 APIs implemented
🔒 Role-based access control on all new endpoints
📊 Transaction ledger ready for financial tracking

**Next Phase**: Add billing logic to add_client endpoint
