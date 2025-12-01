# X-UI Dashboard Monitor - Multi Server

## Overview
A professional web-based monitoring dashboard for multiple X-UI VPN panels, providing secure authentication and comprehensive statistics. It supports an unlimited number of X-UI servers (Sanaei 3X-UI or Alireza X-UI), offering client management capabilities. The project aims to deliver a robust, secure, and user-friendly solution for managing VPN services across various X-UI instances.

## User Preferences
- Dark theme preferred
- English-only interface (LTR)
- Clean, modern design
- Multi-server architecture
- Professional authentication

## System Architecture

### UI/UX Decisions
The dashboard features a responsive design with a mobile-friendly sidebar and stats grid. It utilizes a custom CSS for a modern dark theme and offers touch-friendly action buttons. Tables include horizontal scrolling for mobile. A 3-column QR grid for subscription, JSON, and config links collapses to a single column on mobile.

### Technical Implementations
- **Backend**: Python 3.11 with Flask for web services and API handling.
- **Frontend**: HTML5, CSS3, and Vanilla JavaScript for dynamic content and user interaction.
- **Authentication**: Secure session management with Werkzeug for password hashing and `login_required` decorators. Admin management supports superadmin roles.
- **Server Management**: Supports adding unlimited X-UI panels, auto-detecting panel type, and CRUD operations for servers. Custom subscription and JSON paths, along with a configurable subscription port, are supported per server.
- **Client Management**: Functionality includes enabling/disabling clients, resetting traffic, renewing clients with options for setting days/volume and "Start after first use". QR code generation is available for subscription, subscription JSON, and config links.
- **Data Display**: Dashboard shows statistics (servers, inbounds, clients, traffic), inbound configurations, and detailed traffic/volume usage. Expiry is displayed as remaining days with color-coded badges, supporting "Start after first use" logic. Auto-refresh and manual refresh options are available.

### Feature Specifications
- **Multi-Server Support**: Add, edit, delete, and test connections for unlimited X-UI panels.
- **Authentication & Security**: Professional login, password hashing, admin management, and session-based authentication.
- **Client Actions**: Enable/disable, reset traffic, renew (with "Start after first use" option), and QR code generation for various links.
- **Subscription Port**: Allows specifying a different port for subscription link generation than the X-UI panel's port.

### System Design Choices
- **Database**: PostgreSQL (with SQLite fallback) for data persistence.
- **API Endpoints**: Structured RESTful APIs for authentication, admin management, server management, data retrieval, and client actions.
- **X-UI Panel Integration**: Separate API routes and logic for Sanaei 3X-UI and Alireza X-UI, including authentication, inbound management, and server status.
- **File Structure**: Organized `app.py` as the main application, with `templates/` for HTML, `static/` for CSS, and `pyproject.toml` for dependencies.

## External Dependencies
- **Flask**: Python web framework.
- **Werkzeug**: Security utilities for password hashing.
- **PostgreSQL**: Primary database for data storage (supports SQLite as a fallback).
- **X-UI Panels**: Integrates with Sanaei 3X-UI and Alireza X-UI APIs for server monitoring and client management.