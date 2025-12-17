import os
import io
import re
import json
import base64
import requests
import logging
import qrcode
import uuid
import secrets
import string
import shutil
import glob
import threading
import time
import concurrent.futures
from collections import defaultdict
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from functools import wraps
import copy
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, quote, urlencode
from jdatetime import datetime as jdatetime_class
from sqlalchemy import or_, func, text, inspect, case

APP_VERSION = "1.5.1"
GITHUB_REPO = "yoyoraya/eve-xui-manager"

# Simple in-memory cache for update checks
UPDATE_CACHE = {
    'last_check': 0,
    'data': None,
    'ttl': 3600  # 1 hour cache
}

# کش برای نگهداری وضعیت سرورها در RAM
# این دیتا با هر بار ریستارت برنامه پاک می‌شود (امنیت بالا)
GLOBAL_SERVER_DATA = {
    'last_update': None,
    'inbounds': [],
    'stats': {},
    'servers_status': [],
    'is_updating': False
}

# Prevent overlapping forced refreshes (e.g. after rapid UI actions)
GLOBAL_REFRESH_LOCK = threading.Lock()

# Refresh job tracking (in-memory; per-process)
REFRESH_JOBS = {}  # job_id -> job dict
REFRESH_JOBS_LOCK = threading.Lock()
REFRESH_MAX_JOBS = 50

# Backoff to avoid hammering failing servers during periodic refresh
REFRESH_BACKOFF = {}  # server_id -> {fail_count:int, next_allowed_at:float, last_error:str, last_failed_at:float}
REFRESH_MAX_BACKOFF_SEC = 300


def _utc_iso_now():
    return datetime.utcnow().isoformat()


def _parse_bool(value) -> bool:
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'y', 'on')


def _summarize_job(job):
    if not isinstance(job, dict):
        return None
    # keep payload small
    keys = (
        'id', 'state', 'mode', 'server_id', 'force',
        'created_at', 'started_at', 'finished_at',
        'progress', 'error'
    )
    return {k: job.get(k) for k in keys if k in job}


def _prune_refresh_jobs_locked():
    if len(REFRESH_JOBS) <= REFRESH_MAX_JOBS:
        return
    # prune oldest finished jobs first
    jobs_sorted = sorted(REFRESH_JOBS.items(), key=lambda kv: kv[1].get('created_at_ts', 0))
    to_delete = max(0, len(REFRESH_JOBS) - REFRESH_MAX_JOBS)
    deleted = 0
    for job_id, job in jobs_sorted:
        if deleted >= to_delete:
            break
        if job.get('state') in ('done', 'error'):
            REFRESH_JOBS.pop(job_id, None)
            deleted += 1


def _backoff_get(server_id: int) -> dict:
    try:
        return REFRESH_BACKOFF.get(int(server_id)) or {}
    except Exception:
        return {}


def _backoff_should_skip(server_id: int, now_ts: float) -> bool:
    info = _backoff_get(server_id)
    return float(info.get('next_allowed_at', 0) or 0) > float(now_ts)


def _backoff_record_failure(server_id: int, error: str):
    try:
        sid = int(server_id)
    except Exception:
        return
    now = time.time()
    info = REFRESH_BACKOFF.get(sid) or {'fail_count': 0, 'next_allowed_at': 0, 'last_error': '', 'last_failed_at': 0}
    fail_count = int(info.get('fail_count', 0) or 0) + 1
    # exponential backoff: 5,10,20,40,80,160,300...
    delay = min(REFRESH_MAX_BACKOFF_SEC, (2 ** min(fail_count, 6)) * 5)
    info.update({
        'fail_count': fail_count,
        'next_allowed_at': now + delay,
        'last_error': (error or 'Error')[:400],
        'last_failed_at': now,
    })
    REFRESH_BACKOFF[sid] = info


def _backoff_record_success(server_id: int):
    try:
        sid = int(server_id)
    except Exception:
        return
    if sid in REFRESH_BACKOFF:
        REFRESH_BACKOFF[sid] = {'fail_count': 0, 'next_allowed_at': 0, 'last_error': '', 'last_failed_at': 0}


def _check_server_reachable(server: 'Server', timeout_sec: float = 2.0):
    try:
        base, webpath = extract_base_and_webpath(server.host)
        url = f"{base}{webpath}/login"
        resp = requests.get(url, timeout=timeout_sec, verify=False, allow_redirects=True)
        return (resp.status_code < 500), None
    except Exception as e:
        return False, str(e)


def _update_reachability_status(servers, force: bool = False):
    now_iso = _utc_iso_now()
    now_ts = time.time()
    existing_statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
    status_map = {}
    for st in existing_statuses:
        try:
            if isinstance(st, dict) and 'server_id' in st:
                status_map[int(st.get('server_id'))] = st
        except Exception:
            continue

    for srv in servers or []:
        try:
            sid = int(srv.id)
        except Exception:
            continue
        if not force and _backoff_should_skip(sid, now_ts):
            info = _backoff_get(sid)
            st = status_map.get(sid) or {'server_id': sid}
            st['reachable'] = False
            st['reachable_error'] = f"Backoff (until {int(info.get('next_allowed_at', 0) or 0)})"
            st['reachable_checked_at'] = now_iso
            status_map[sid] = st
            continue

        ok, err = _check_server_reachable(srv)
        st = status_map.get(sid) or {'server_id': sid}
        st['reachable'] = bool(ok)
        st['reachable_error'] = None if ok else (err or 'Unreachable')
        st['reachable_checked_at'] = now_iso
        status_map[sid] = st

        if ok:
            _backoff_record_success(sid)
        else:
            _backoff_record_failure(sid, st['reachable_error'])

    # write back preserving server order (if we can)
    ordered = []
    try:
        id_order = [int(s.id) for s in servers]
        for sid in id_order:
            if sid in status_map:
                ordered.append(status_map[sid])
        # include any extra statuses that were not part of the requested servers
        for sid, st in status_map.items():
            if sid not in set(id_order):
                ordered.append(st)
    except Exception:
        ordered = list(status_map.values())
    GLOBAL_SERVER_DATA['servers_status'] = ordered
    GLOBAL_SERVER_DATA['last_update'] = _utc_iso_now()


def _run_refresh_job(job_id: str):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
        if not job:
            return
        job['state'] = 'running'
        job['started_at'] = _utc_iso_now()

    try:
        # Important: background threads must run inside app context for SQLAlchemy.
        with app.app_context():
            with GLOBAL_REFRESH_LOCK:
                GLOBAL_SERVER_DATA['is_updating'] = True
                try:
                    mode = (job.get('mode') or 'full').strip().lower()
                    server_id = job.get('server_id')
                    force = bool(job.get('force'))

                    if mode == 'status':
                        servers_q = Server.query.filter_by(enabled=True)
                        if server_id:
                            servers_q = servers_q.filter(Server.id == int(server_id))
                        servers = servers_q.all()
                        _update_reachability_status(servers, force=force)
                    else:
                        if server_id:
                            try:
                                fetch_and_update_server_data(int(server_id))
                                _backoff_record_success(int(server_id))
                            except Exception as e:
                                _backoff_record_failure(int(server_id), str(e))
                                raise
                        else:
                            fetch_and_update_global_data(force=force)
                finally:
                    GLOBAL_SERVER_DATA['is_updating'] = False

        with REFRESH_JOBS_LOCK:
            job = REFRESH_JOBS.get(job_id) or {}
            job['state'] = 'done'
            job['finished_at'] = _utc_iso_now()
            REFRESH_JOBS[job_id] = job
            _prune_refresh_jobs_locked()
    except Exception as e:
        with REFRESH_JOBS_LOCK:
            job = REFRESH_JOBS.get(job_id) or {}
            job['state'] = 'error'
            job['error'] = str(e)
            job['finished_at'] = _utc_iso_now()
            REFRESH_JOBS[job_id] = job
            _prune_refresh_jobs_locked()


def enqueue_refresh_job(mode: str = 'full', server_id=None, force: bool = False):
    mode_norm = (mode or 'full').strip().lower()
    if mode_norm not in ('full', 'status'):
        mode_norm = 'full'

    sid = None
    try:
        if server_id not in (None, '', 'null'):
            sid = int(server_id)
    except Exception:
        sid = None

    scope_key = f"{mode_norm}:{sid if sid is not None else 'all'}"
    with REFRESH_JOBS_LOCK:
        for existing in REFRESH_JOBS.values():
            if existing.get('scope_key') == scope_key and existing.get('state') in ('queued', 'running'):
                return existing

        job_id = secrets.token_hex(8)
        job = {
            'id': job_id,
            'scope_key': scope_key,
            'mode': mode_norm,
            'server_id': sid,
            'force': bool(force),
            'state': 'queued',
            'created_at': _utc_iso_now(),
            'created_at_ts': time.time(),
            'started_at': None,
            'finished_at': None,
            'progress': {},
            'error': None,
        }
        REFRESH_JOBS[job_id] = job
        _prune_refresh_jobs_locked()

    t = threading.Thread(target=_run_refresh_job, args=(job_id,), daemon=True)
    t.start()
    return job


def _recompute_global_stats_from_server_statuses(server_statuses):
    """Recompute aggregate stats from cached per-server stats."""
    total_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,
        "active_clients": 0,
        "inactive_clients": 0,
        "not_started_clients": 0,
        "unlimited_expiry_clients": 0,
        "unlimited_volume_clients": 0,
        "upload_raw": 0,
        "download_raw": 0,
    }

    for status in server_statuses or []:
        if not isinstance(status, dict) or not status.get("success"):
            continue
        stats = status.get("stats")
        if not isinstance(stats, dict):
            continue
        for k in list(total_stats.keys()):
            v = stats.get(k, 0)
            if isinstance(v, int):
                total_stats[k] += v

    total_stats["total_upload"] = format_bytes(total_stats["upload_raw"])
    total_stats["total_download"] = format_bytes(total_stats["download_raw"])
    total_stats["total_traffic"] = format_bytes(total_stats["upload_raw"] + total_stats["download_raw"])
    return total_stats


def fetch_and_update_server_data(server_id: int):
    """Fetch a single server's inbounds and update GLOBAL_SERVER_DATA in-place."""
    server = db.session.get(Server, int(server_id))
    if not server or not server.enabled:
        raise ValueError("Server not found or disabled")

    admin_user = Admin.query.filter(or_(Admin.is_superadmin == True, Admin.role == 'superadmin')).first()
    if not admin_user:
        admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

    session_obj, error = get_xui_session(server)
    if error:
        raise RuntimeError(error)

    inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_error:
        raise RuntimeError(fetch_error)

    if persist_detected_panel_type(server, detected_type):
        app.logger.info(f"Detected panel type for server {server.id} as {detected_type}")

    processed, stats = process_inbounds(inbounds, server, admin_user, '*', {})

    # Update cache atomically under lock
    # - Replace only this server's inbounds
    # - Preserve the previous ordering position (do NOT move the server's block to the end)
    # - Update per-server status stats
    # - Recompute aggregate stats
    existing_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
    new_block = list(processed or [])

    # Find the first occurrence index of this server in the existing list (if any)
    first_idx = None
    for idx, item in enumerate(existing_inbounds):
        try:
            if int(item.get('server_id', -1)) == int(server.id):
                first_idx = idx
                break
        except Exception:
            continue

    without_server = []
    for item in existing_inbounds:
        try:
            if int(item.get('server_id', -1)) == int(server.id):
                continue
        except Exception:
            pass
        without_server.append(item)

    if first_idx is None:
        # Server didn't exist in cache before: append to end
        GLOBAL_SERVER_DATA['inbounds'] = without_server + new_block
    else:
        # Insert new block at the previous position
        insert_at = min(max(first_idx, 0), len(without_server))
        GLOBAL_SERVER_DATA['inbounds'] = without_server[:insert_at] + new_block + without_server[insert_at:]

    statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
    updated = False
    for st in statuses:
        if isinstance(st, dict) and int(st.get('server_id', -1)) == int(server.id):
            st.update({"server_id": server.id, "success": True, "stats": stats, "panel_type": server.panel_type})
            updated = True
            break
    if not updated:
        statuses.append({"server_id": server.id, "success": True, "stats": stats, "panel_type": server.panel_type})
    GLOBAL_SERVER_DATA['servers_status'] = statuses

    GLOBAL_SERVER_DATA['stats'] = _recompute_global_stats_from_server_statuses(statuses)
    GLOBAL_SERVER_DATA['last_update'] = datetime.utcnow().isoformat()

# Guard to avoid starting background threads multiple times (important for gunicorn workers / dev reload)
BACKGROUND_THREADS_STARTED = False

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Use SQLite by default, but allow override via DATABASE_URL
db_url = os.environ.get("DATABASE_URL")
if db_url:
    db_url = str(db_url).strip()
    # Heroku-style scheme; SQLAlchemy expects postgresql://
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[len("postgres://"):]
else:
    db_path = os.path.join(app.instance_path, 'servers.db')
    os.makedirs(app.instance_path, exist_ok=True)
    db_url = f"sqlite:///{db_path}"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 1800,
    'pool_pre_ping': True
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

RECEIPT_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'heic', 'heif', 'pdf'}
RECEIPTS_DIR = os.path.join(app.instance_path, 'receipts')
os.makedirs(RECEIPTS_DIR, exist_ok=True)

BACKUP_DIR = os.path.join(app.instance_path, 'backups')
os.makedirs(BACKUP_DIR, exist_ok=True)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5000 per day", "500 per hour"]
)

db = SQLAlchemy(app)

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

# --- MODELS ---

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')
    is_superadmin = db.Column(db.Boolean, default=False)
    credit = db.Column(db.Integer, default=0)
    allowed_servers = db.Column(db.Text, default='[]')
    enabled = db.Column(db.Boolean, default=True)
    discount_percent = db.Column(db.Integer, default=0)
    custom_cost_per_day = db.Column(db.Integer, nullable=True)
    custom_cost_per_gb = db.Column(db.Integer, nullable=True)
    telegram_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    transactions = db.relationship('Transaction', backref='admin', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'is_superadmin': self.is_superadmin,
            'credit': self.credit,
            'allowed_servers': parse_allowed_servers(self.allowed_servers),
            'enabled': self.enabled,
            'discount_percent': self.discount_percent,
            'custom_cost_per_day': self.custom_cost_per_day,
            'custom_cost_per_gb': self.custom_cost_per_gb,
            'telegram_id': self.telegram_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    panel_type = db.Column(db.String(50), default='auto')
    sub_path = db.Column(db.String(50), default='/sub/')
    json_path = db.Column(db.String(50), default='/json/')
    sub_port = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'username': self.username,
            'enabled': self.enabled,
            'panel_type': self.panel_type,
            'sub_path': self.sub_path,
            'json_path': self.json_path,
            'sub_port': self.sub_port,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SubAppConfig(db.Model):
    __tablename__ = 'sub_app_configs'
    id = db.Column(db.Integer, primary_key=True)
    app_code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100))
    os_type = db.Column(db.String(20), default='android')  # android, ios, windows
    is_enabled = db.Column(db.Boolean, default=True)
    title_fa = db.Column(db.String(200))
    description_fa = db.Column(db.Text)
    title_en = db.Column(db.String(200))
    description_en = db.Column(db.Text)
    download_link = db.Column(db.String(500))
    store_link = db.Column(db.String(500))
    tutorial_link = db.Column(db.String(500))
    
    def to_dict(self):
        return {
            'id': self.id,
            'app_code': self.app_code,
            'name': self.name,
            'os_type': self.os_type or 'android',
            'is_enabled': self.is_enabled,
            'title_fa': self.title_fa,
            'description_fa': self.description_fa,
            'title_en': self.title_en,
            'description_en': self.description_en,
            'download_link': self.download_link,
            'store_link': self.store_link,
            'tutorial_link': self.tutorial_link
        }

class FAQ(db.Model):
    __tablename__ = 'faqs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)  # HTML content
    image_url = db.Column(db.String(500))
    video_url = db.Column(db.String(500))
    platform = db.Column(db.String(20), default='android')  # android, ios, windows
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'image_url': self.image_url,
            'video_url': self.video_url,
            'platform': self.platform or 'android',
            'is_enabled': self.is_enabled
        }

class Package(db.Model):
    __tablename__ = 'packages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    days = db.Column(db.Integer, nullable=False)
    volume = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    reseller_price = db.Column(db.Integer, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'days': self.days,
            'volume': self.volume,
            'price': self.price,
            'reseller_price': self.reseller_price,
            'enabled': self.enabled
        }

class SystemConfig(db.Model):
    __tablename__ = 'system_configs'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(200))


RECEIPT_STATUS_PENDING = 'pending'
RECEIPT_STATUS_AUTO_PENDING = 'auto_pending'
RECEIPT_STATUS_APPROVED = 'approved'
RECEIPT_STATUS_AUTO_APPROVED = 'auto_approved'
RECEIPT_STATUS_REJECTED = 'rejected'


class BankCard(db.Model):
    __tablename__ = 'bank_cards'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    bank_name = db.Column(db.String(120))
    owner_name = db.Column(db.String(120))
    card_number = db.Column(db.String(32))
    iban = db.Column(db.String(34))
    account_number = db.Column(db.String(64))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def masked_card(self):
        if not self.card_number:
            return None
        cleaned = ''.join(filter(str.isdigit, self.card_number))
        if len(cleaned) <= 4:
            return cleaned
        return f"{'*' * (len(cleaned) - 4)}{cleaned[-4:]}"

    def to_dict(self):
        return {
            'id': self.id,
            'label': self.label,
            'bank_name': self.bank_name,
            'owner_name': self.owner_name,
            'card_number': self.card_number,
            'masked_card': self.masked_card(),
            'iban': self.iban,
            'account_number': self.account_number,
            'notes': self.notes,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class NotificationTemplate(db.Model):
    __tablename__ = 'notification_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='client_created')
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'type': self.type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)

class ManualReceipt(db.Model):
    __tablename__ = 'manual_receipts'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'))
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), default='IRT')
    deposit_at = db.Column(db.DateTime)
    reference_code = db.Column(db.String(120))
    image_path = db.Column(db.String(300))
    status = db.Column(db.String(32), default=RECEIPT_STATUS_PENDING, index=True)
    auto_deadline = db.Column(db.DateTime, index=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('admins.id'))
    reviewed_at = db.Column(db.DateTime)
    rejection_reason = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    admin = db.relationship('Admin', foreign_keys=[admin_id], backref=db.backref('receipts', lazy=True))
    reviewer = db.relationship('Admin', foreign_keys=[reviewer_id])
    card = db.relationship('BankCard', backref=db.backref('receipts', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'admin': {'id': self.admin.id, 'username': self.admin.username} if self.admin else None,
            'card': self.card.to_dict() if self.card else None,
            'amount': self.amount,
            'currency': self.currency,
            'deposit_at': self.deposit_at.isoformat() if self.deposit_at else None,
            'reference_code': self.reference_code,
            'image_path': self.image_path,
            'status': self.status,
            'auto_deadline': self.auto_deadline.isoformat() if self.auto_deadline else None,
            'reviewer': {'id': self.reviewer.id, 'username': self.reviewer.username} if self.reviewer else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'rejection_reason': self.rejection_reason,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AutoApprovalWindow(db.Model):
    __tablename__ = 'auto_approval_windows'
    id = db.Column(db.Integer, primary_key=True)
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    max_amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='enabled')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_active(self, moment=None):
        moment = moment or datetime.utcnow()
        if self.status != 'enabled':
            return False
        return self.starts_at <= moment <= self.ends_at

    def to_dict(self):
        return {
            'id': self.id,
            'starts_at': self.starts_at.isoformat() if self.starts_at else None,
            'ends_at': self.ends_at.isoformat() if self.ends_at else None,
            'max_amount': self.max_amount,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Payment(db.Model):
    """Track incoming payments from customers"""
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'), nullable=True)  # کارت مقصد (شما)
    sender_card = db.Column(db.String(32))  # شماره کارت مشتری (اختیاری)
    sender_name = db.Column(db.String(120))  # نام فرستنده
    amount = db.Column(db.Integer, nullable=False)  # مبلغ به تومان
    payment_date = db.Column(db.DateTime, nullable=False)  # تاریخ واریز
    client_email = db.Column(db.String(100))  # مربوط به کدوم کلاینت
    description = db.Column(db.Text)  # توضیحات
    verified = db.Column(db.Boolean, default=False)  # تایید شده؟
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    admin = db.relationship('Admin', backref=db.backref('payments', lazy=True))
    card = db.relationship('BankCard', backref=db.backref('payments', lazy=True))
    
    def to_dict(self):
        card_info = None
        if self.card:
            card_info = {
                'id': self.card.id,
                'label': self.card.label,
                'bank_name': self.card.bank_name,
                'masked_card': self.card.masked_card()
            }
        
        admin_info = None
        if self.admin:
            admin_info = {
                'id': self.admin.id,
                'username': self.admin.username,
                'role': self.admin.role
            }
        
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'admin': admin_info,
            'card_id': self.card_id,
            'card': card_info,
            'sender_card': self.sender_card,
            'sender_name': self.sender_name,
            'amount': self.amount,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None,
            'payment_date_jalali': format_jalali(self.payment_date),
            'client_email': self.client_email,
            'description': self.description,
            'verified': self.verified,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    card_id = db.Column(db.Integer, db.ForeignKey('bank_cards.id'), nullable=True)  # کارت مقصد (شما)
    sender_card = db.Column(db.String(32), nullable=True)  # شماره کارت مشتری
    sender_name = db.Column(db.String(120), nullable=True)  # نام فرستنده
    client_email = db.Column(db.String(100), nullable=True)  # ایمیل کلاینت مرتبط
    amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(20))
    category = db.Column(db.String(16), default='usage', nullable=False)  # 'income', 'expense', 'usage'
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    server = db.relationship('Server', backref='transactions', lazy=True)
    card = db.relationship('BankCard', backref='transactions', lazy=True)
    
    def to_dict(self):
        admin_info = None
        if hasattr(self, 'admin') and self.admin:
            admin_info = {
                'id': self.admin.id,
                'username': self.admin.username,
                'role': self.admin.role
            }
        
        server_info = None
        if self.server:
            server_info = {
                'id': self.server.id,
                'name': self.server.name
            }
        
        card_info = None
        if self.card:
            card_info = {
                'id': self.card.id,
                'label': self.card.label,
                'bank_name': self.card.bank_name,
                'masked_card': self.card.masked_card()
            }
            
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'server_id': self.server_id,
            'server': server_info,
            'card_id': self.card_id,
            'card': card_info,
            'sender_card': self.sender_card,
            'sender_name': self.sender_name,
            'client_email': self.client_email,
            'amount': self.amount,
            'type': self.type,
            'description': self.description,
            'date': self.created_at.isoformat() if self.created_at else None,
            'date_jalali': format_jalali(self.created_at),
            'admin': admin_info
        }

class ClientOwnership(db.Model):
    __tablename__ = 'client_ownerships'
    id = db.Column(db.Integer, primary_key=True)
    reseller_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    inbound_id = db.Column(db.Integer, nullable=True)
    client_email = db.Column(db.String(100), nullable=False)
    client_uuid = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    price = db.Column(db.Integer, default=0)
    
    reseller = db.relationship('Admin', backref=db.backref('clients', lazy=True))
    server = db.relationship('Server', backref=db.backref('owned_clients', lazy=True))

class PanelAPI(db.Model):
    __tablename__ = 'panel_apis'
    id = db.Column(db.Integer, primary_key=True)
    panel_type = db.Column(db.String(50), unique=True, nullable=False)  # 'sanaei', 'alireza', etc
    display_name = db.Column(db.String(100))
    login_endpoint = db.Column(db.String(100))
    
    # Inbound endpoints
    inbounds_list = db.Column(db.String(200))
    inbounds_get = db.Column(db.String(200))
    inbounds_add = db.Column(db.String(200))
    inbounds_update = db.Column(db.String(200))
    inbounds_delete = db.Column(db.String(200))
    
    # Client endpoints
    client_add = db.Column(db.String(200))
    client_update = db.Column(db.String(200))
    client_delete = db.Column(db.String(200))
    client_reset_traffic = db.Column(db.String(200))
    client_get_traffic = db.Column(db.String(200))
    
    # Server endpoints
    server_status = db.Column(db.String(200))
    server_restart = db.Column(db.String(200))
    server_stop = db.Column(db.String(200))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'panel_type': self.panel_type,
            'display_name': self.display_name,
            'login_endpoint': self.login_endpoint,
            'inbounds_list': self.inbounds_list,
            'inbounds_get': self.inbounds_get,
            'client_add': self.client_add,
            'client_reset_traffic': self.client_reset_traffic
        }

def get_panel_api(panel_type):
    """Return PanelAPI config for given panel_type or None."""
    if not panel_type or panel_type == 'auto':
        return None
    return PanelAPI.query.filter_by(panel_type=panel_type).first()


CLIENT_UPDATE_FALLBACKS = [
    "/panel/api/inbounds/updateClient/:clientId",
    "/panel/api/inbounds/:id/updateClient/:clientId",
    "/xui/API/inbounds/updateClient/:clientId",
    "/xui/inbound/updateClient/:clientId"
]

CLIENT_RESET_FALLBACKS = [
    "/panel/api/inbounds/:id/resetClientTraffic/:email",
    "/xui/API/inbounds/:id/resetClientTraffic/:email",
    "/xui/inbounds/:id/resetClientTraffic/:email",
    "/xui/inbound/:id/resetClientTraffic/:email"
]

CLIENT_DELETE_FALLBACKS = [
    "/panel/api/inbounds/:id/delClient/:clientId",
    "/xui/API/inbounds/:id/delClient/:clientId",
    "/xui/inbound/delClient/:clientId"
]


def collect_endpoint_templates(panel_type, attr_name, fallbacks):
    """Return ordered list of endpoint templates for the requested action."""
    templates = []
    panel_api = get_panel_api(panel_type)
    if panel_api:
        value = getattr(panel_api, attr_name, None)
        if value:
            templates.append(value)
    for api in PanelAPI.query.all():
        value = getattr(api, attr_name, None)
        if value and value not in templates:
            templates.append(value)
    for item in fallbacks:
        if item not in templates:
            templates.append(item)
    return templates


def build_panel_url(host, template, replacements):
    if not template:
        return None
    endpoint = template
    for key, value in (replacements or {}).items():
        if value is None:
            continue
        safe_value = quote(str(value), safe='')
        endpoint = endpoint.replace(f":{key}", safe_value).replace(f"{{{key}}}", safe_value)
    if endpoint.startswith('http://') or endpoint.startswith('https://'):
        return endpoint
    base, webpath = extract_base_and_webpath(host)
    endpoint_clean = endpoint if endpoint.startswith('/') else f"/{endpoint}"
    return f"{base}{webpath}{endpoint_clean}"

with app.app_context():
    db.create_all()
    
    # Check for telegram_id column in admins table
    try:
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('admins')]
        print(f"Current columns in admins: {columns}")
        if 'telegram_id' not in columns:
            print("telegram_id column missing, attempting to add...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE admins ADD COLUMN telegram_id VARCHAR(100)'))
                conn.commit()
            print("Added telegram_id column to admins table")
        else:
            print("telegram_id column already exists")
    except Exception as e:
        print(f"Migration error: {e}")

    # Ensure sender_name exists on transactions table (older DBs)
    try:
        inspector = inspect(db.engine)
        tx_columns = [c['name'] for c in inspector.get_columns('transactions')]
        if 'sender_name' not in tx_columns:
            print("sender_name column missing on transactions, attempting to add...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE transactions ADD COLUMN sender_name VARCHAR(120)'))
                conn.commit()
            print("Added sender_name column to transactions table")
    except Exception as e:
        print(f"Migration error (transactions.sender_name): {e}")
    
    # Initialize PanelAPI data
    if not PanelAPI.query.first():
        panel_apis = [
            PanelAPI(
                panel_type='sanaei',
                display_name='3X-UI (Sanaei)',
                login_endpoint='/login',
                inbounds_list='/panel/api/inbounds/list',
                inbounds_get='/panel/api/inbounds/get/:id',
                inbounds_add='/panel/api/inbounds/add',
                inbounds_update='/panel/api/inbounds/update/:id',
                inbounds_delete='/panel/api/inbounds/del/:id',
                client_add='/panel/api/inbounds/addClient',
                client_update='/panel/api/inbounds/updateClient/:clientId',
                client_delete='/panel/api/inbounds/:id/delClient/:clientId',
                client_reset_traffic='/panel/api/inbounds/:id/resetClientTraffic/:email',
                client_get_traffic='/panel/api/inbounds/getClientTraffics/:email',
                server_status='/panel/api/server/status',
                server_restart='/panel/api/server/restartXrayService',
                server_stop='/panel/api/server/stopXrayService'
            ),
            PanelAPI(
                panel_type='alireza',
                display_name='X-UI (Alireza)',
                login_endpoint='/login',
                inbounds_list='/xui/API/inbounds/',
                inbounds_get='/xui/API/inbounds/get/:id',
                inbounds_add='/xui/API/inbounds/add',
                inbounds_update='/xui/API/inbounds/update/:id',
                inbounds_delete='/xui/API/inbounds/del/:id',
                client_add='/xui/API/inbounds/addClient/',
                client_update='/xui/API/inbounds/updateClient/:clientId',
                client_delete='/xui/API/inbounds/:id/delClient/:clientId',
                client_reset_traffic='/xui/API/inbounds/:id/resetClientTraffic/:email',
                client_get_traffic='/xui/API/inbounds/getClientTraffics/:email',
                server_status='/xui/API/server/status',
                server_restart='/xui/API/server/restartXrayService',
                server_stop='/xui/API/server/stopXrayService'
            )
        ]
        db.session.add_all(panel_apis)
    
    if Admin.query.count() == 0:
        initial_username = os.environ.get("INITIAL_ADMIN_USERNAME", "admin")
        default_admin = Admin(
            username=initial_username,
            is_superadmin=True,
            role='superadmin',
            enabled=True,
            allowed_servers='*'
        )
        initial_password = os.environ.get("INITIAL_ADMIN_PASSWORD", "admin")
        default_admin.set_password(initial_password)
        db.session.add(default_admin)
        
        if not SubAppConfig.query.first():
            apps_list = [
                SubAppConfig(app_code='v2rayng', name='v2rayNG (Android)', title_fa='راهنمای v2rayNG', description_fa='۱. برنامه را دانلود کنید.\n۲. لینک را کپی و Import کنید.', title_en='v2rayNG Guide', description_en='1. Download app.\n2. Copy link and Import.', download_link='https://github.com/2dust/v2rayNG/releases/download/1.8.19/v2rayNG_1.8.19.apk', store_link='https://play.google.com/store/apps/details?id=com.v2ray.ang'),
                SubAppConfig(app_code='nekobox', name='NekoBox (Android)', title_fa='راهنمای NekoBox', description_fa='جایگزین عالی برای v2rayNG.', title_en='NekoBox Guide', description_en='Great alternative.', download_link='https://github.com/MatsuriDayo/NekoBoxForAndroid/releases'),
                SubAppConfig(app_code='streisand', name='Streisand (iOS)', title_fa='راهنمای Streisand', description_fa='پیشنهاد برای آیفون.', title_en='Streisand Guide', description_en='Recommended for iOS.', store_link='https://apps.apple.com/us/app/streisand/id6450534064')
            ]
            db.session.add_all(apps_list)
        
        if not SystemConfig.query.filter_by(key='cost_per_gb').first():
            db.session.add(SystemConfig(key='cost_per_gb', value='2000'))
        if not SystemConfig.query.filter_by(key='cost_per_day').first():
            db.session.add(SystemConfig(key='cost_per_day', value='500'))
        
        db.session.commit()

# --- HELPERS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            # For API endpoints, AJAX/XHR requests, or requests that accept JSON, return JSON errors
            is_api_path = request.path.startswith('/api/')
            accepts_json = 'application/json' in (request.headers.get('Accept') or '')
            is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
            if is_api_path or accepts_json or is_xhr:
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        admin = db.session.get(Admin, session['admin_id'])
        if not admin or (admin.role != 'superadmin' and not admin.is_superadmin):
            return jsonify({"success": False, "error": "Access Denied: SuperAdmin only"}), 403
        return f(*args, **kwargs)
    return decorated_function

def calculate_reseller_price(user, base_price=None, package=None, cost_type=None):
    """
    Calculate price for a reseller based on their settings.
    """
    if user.role != 'reseller':
        if package: return package.price
        return base_price if base_price is not None else 0

    # 1. Custom Plan Logic (Day/GB rates)
    if cost_type == 'day':
        if user.custom_cost_per_day is not None:
            return user.custom_cost_per_day
        discount = user.discount_percent or 0
        return int(base_price * (1 - discount / 100)) if base_price else 0
        
    if cost_type == 'gb':
        if user.custom_cost_per_gb is not None:
            return user.custom_cost_per_gb
        discount = user.discount_percent or 0
        return int(base_price * (1 - discount / 100)) if base_price else 0

    # 2. Package Logic
    if package:
        # Priority 1: Reseller Price on Package (Global Reseller Price)
        # If a specific reseller price is set on the package, use it.
        # However, if the user has a specific discount, maybe they want discount off the standard price?
        # Let's assume: Reseller Price is a fixed override.
        if package.reseller_price is not None and package.reseller_price > 0:
             # If user has a discount, we might want to apply it to the standard price and compare?
             # Or just take the reseller price.
             # Let's stick to: Reseller Price > Discounted Standard Price.
             return package.reseller_price
            
        # Priority 2: Discount on Standard Price
        discount = user.discount_percent or 0
        return int(package.price * (1 - discount / 100))

    return base_price if base_price is not None else 0

def get_config(key, default=0):
    conf = db.session.get(SystemConfig, key)
    return int(conf.value) if conf else default

def log_transaction(user_id, amount, type, desc, server_id=None, card_id=None, sender_card=None, category='usage', client_email=None):
    trans = Transaction(
        admin_id=user_id,
        amount=amount,
        type=type,
        description=desc,
        server_id=server_id,
        card_id=card_id,
        sender_card=sender_card,
        category=category,
        client_email=client_email
    )
    db.session.add(trans)

@app.context_processor
def inject_wallet_credit():
    wallet_credit = 0
    admin_id = session.get('admin_id')
    if admin_id:
        user = db.session.get(Admin, admin_id)
        if user:
            wallet_credit = user.credit or 0
    return {"wallet_credit": wallet_credit}

def format_jalali(dt):
    if not dt:
        return None
    try:
        # Convert UTC to Tehran (+3:30)
        dt_tehran = dt + timedelta(hours=3, minutes=30)
        jalali_date = jdatetime_class.fromgregorian(datetime=dt_tehran)
        return jalali_date.strftime('%Y/%m/%d %H:%M')
    except Exception:
        return dt.isoformat() if dt else None

EMAIL_IN_DESCRIPTION = re.compile(r'([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)$')

_DIGIT_TRANSLATION = str.maketrans({
    '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4', '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9',
    '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4', '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9',
})


def parse_amount_to_int(value):
    """Parse amount input to int.

    Accepts strings with commas/spaces and Persian/Arabic digits.
    Returns None if cannot parse.
    """
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        if not s:
            return None
        s = s.translate(_DIGIT_TRANSLATION)
        # Keep digits only (strip separators/currency)
        s = re.sub(r'[^0-9]', '', s)
        if not s:
            return None
        return int(s)
    except Exception:
        return None

def extract_email_from_description(description):
    if not description:
        return None
    match = EMAIL_IN_DESCRIPTION.search(description.strip())
    if not match:
        return None
    email = match.group(1).strip().lower()
    return email.rstrip('.,;') or None

def parse_jalali_date(date_str, end_of_day=False):
    if not date_str:
        return None
    normalized = date_str.strip()
    if not normalized:
        return None
    patterns = ['%Y/%m/%d %H:%M', '%Y-%m-%d %H:%M', '%Y/%m/%d', '%Y-%m-%d']
    for pattern in patterns:
        try:
            j_date = jdatetime_class.strptime(normalized, pattern)
            gregorian = j_date.togregorian()
            dt = None
            if 'H' not in pattern:
                day = gregorian.date()
                time_part = datetime.max.time() if end_of_day else datetime.min.time()
                dt = datetime.combine(day, time_part)
            else:
                dt = gregorian
            
            # Convert Tehran to UTC (-3:30)
            return dt - timedelta(hours=3, minutes=30)
        except ValueError:
            continue
    return None

def parse_allowed_servers(raw_value):
    if not raw_value:
        return []
    if isinstance(raw_value, list):
        return raw_value
    normalized = str(raw_value).strip()
    if normalized == '*':
        return '*'
    if normalized.startswith('"') and normalized.endswith('"'):
        inner = normalized.strip('"')
        if inner == '*':
            return '*'
        # Attempt to decode double-encoded JSON strings
        try:
            decoded_inner = json.loads(inner)
            return decoded_inner if decoded_inner is not None else []
        except Exception:
            pass
    try:
        parsed = json.loads(normalized)
        if isinstance(parsed, str) and parsed.strip() == '*':
            return '*'
        return parsed if isinstance(parsed, list) else parsed
    except Exception:
        return []

def serialize_allowed_servers(value):
    """Serialize server/inbound permissions.

    Supports legacy formats (list of server ids or '*') and new structured
    payloads like [{'server_id': 1, 'inbounds': [10, 12]}, ...].
    """

    def _normalize_inbounds(val):
        if val is None:
            return '*'
        if val == '*' or (isinstance(val, str) and val.strip() == '*'):
            return '*'
        if isinstance(val, list):
            normalized = []
            for v in val:
                try:
                    normalized.append(int(v))
                except (TypeError, ValueError):
                    continue
            return normalized
        try:
            return [int(val)]
        except (TypeError, ValueError):
            return []

    if value == '*' or (isinstance(value, str) and value.strip() == '*'):
        return '*'

    # Parse JSON strings if provided
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return serialize_allowed_servers(parsed)
        except Exception:
            # Fallback for simple comma-separated server IDs
            parts = [p.strip() for p in value.split(',') if p.strip()]
            try:
                return serialize_allowed_servers([int(p) for p in parts])
            except Exception:
                return json.dumps([])

    if isinstance(value, dict):
        value = [value]

    normalized = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                server_id = item.get('server_id') or item.get('server') or item.get('id')
                try:
                    server_id = int(server_id)
                except (TypeError, ValueError):
                    continue
                inbounds = _normalize_inbounds(item.get('inbounds', '*'))
                normalized.append({'server_id': server_id, 'inbounds': '*' if inbounds == '*' else inbounds})
            else:
                try:
                    server_id = int(item)
                    normalized.append({'server_id': server_id, 'inbounds': '*'})
                except (TypeError, ValueError):
                    continue

    if not normalized:
        return json.dumps([])

    # Merge duplicates and keep unique inbound lists per server
    merged = {}
    for entry in normalized:
        sid = entry['server_id']
        inb = entry['inbounds']
        if sid not in merged:
            merged[sid] = inb
            continue
        existing = merged[sid]
        if existing == '*' or inb == '*':
            merged[sid] = '*'
        else:
            merged[sid] = sorted(list(set(existing) | set(inb)))

    final_list = [{'server_id': sid, 'inbounds': val} for sid, val in merged.items()]
    return json.dumps(final_list)

def resolve_allowed_servers(raw_value):
    """Backward-compatible resolver returning only server IDs or '*'."""
    allowed_map = resolve_allowed_map(raw_value)
    if allowed_map == '*':
        return '*'
    return list(allowed_map.keys())


def resolve_allowed_map(raw_value):
    """Return mapping of server_id -> inbound rule ('*' or set of ids)."""
    parsed = parse_allowed_servers(raw_value)
    if parsed == '*':
        return '*'

    allowed_map = {}
    items = parsed
    if isinstance(items, dict):
        items = [items]

    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                server_id = item.get('server_id') or item.get('server') or item.get('id')
                try:
                    server_id = int(server_id)
                except (TypeError, ValueError):
                    continue
                inbounds_raw = item.get('inbounds', '*')
                inbounds = set()
                if inbounds_raw == '*' or (isinstance(inbounds_raw, str) and inbounds_raw.strip() == '*'):
                    allowed_map[server_id] = '*'
                    continue
                if isinstance(inbounds_raw, list):
                    for v in inbounds_raw:
                        try:
                            inbounds.add(int(v))
                        except (TypeError, ValueError):
                            continue
                else:
                    try:
                        inbounds.add(int(inbounds_raw))
                    except (TypeError, ValueError):
                        pass
                allowed_map[server_id] = inbounds
            else:
                try:
                    sid = int(item)
                    allowed_map[sid] = '*'
                except (TypeError, ValueError):
                    continue
    return allowed_map


def get_reseller_access_maps(user):
    """Return (allowed_map, assignment_map) for a reseller user."""
    if not user or user.role != 'reseller':
        return '*', {}

    allowed_map = resolve_allowed_map(user.allowed_servers)
    assignments = defaultdict(set)

    ownerships = ClientOwnership.query.filter_by(reseller_id=user.id).all()
    for own in ownerships:
        try:
            sid = int(own.server_id)
        except (TypeError, ValueError):
            continue
        if own.inbound_id is not None:
            try:
                assignments[sid].add(int(own.inbound_id))
            except (TypeError, ValueError):
                continue

    return allowed_map, assignments


def is_server_accessible(server_id, allowed_map, assignments):
    if allowed_map == '*':
        return True
    if server_id in assignments:
        return True
    return server_id in allowed_map


def is_inbound_accessible(server_id, inbound_id, allowed_map, assignments):
    if allowed_map == '*':
        return True

    # Access via explicit assignment
    assigned = assignments.get(server_id, set())
    if '*' in assigned or inbound_id in assigned:
        return True

    server_rule = allowed_map.get(server_id)
    if server_rule == '*':
        return True
    if isinstance(server_rule, (set, list, tuple)):
        return inbound_id in server_rule
    return False

def parse_iso_datetime(value):
    if not value:
        return None
    try:
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)
    except Exception:
        try:
            # fallback for "2024-12-01 12:00"
            return datetime.strptime(value, '%Y-%m-%d %H:%M')
        except Exception:
            return None

def allowed_receipt_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in RECEIPT_ALLOWED_EXTENSIONS

def save_receipt_file(file_storage):
    if not file_storage or not allowed_receipt_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    subdir = datetime.utcnow().strftime('%Y/%m')
    dest_dir = os.path.join(RECEIPTS_DIR, subdir)
    os.makedirs(dest_dir, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    safe_name = secure_filename(unique_name)
    relative_path = os.path.join('receipts', subdir, safe_name)
    full_path = os.path.join(app.instance_path, relative_path)
    file_storage.save(full_path)
    return relative_path

def get_active_auto_window(now=None):
    now = now or datetime.utcnow()
    return AutoApprovalWindow.query.filter(
        AutoApprovalWindow.status == 'enabled',
        AutoApprovalWindow.starts_at <= now,
        AutoApprovalWindow.ends_at >= now
    ).order_by(AutoApprovalWindow.ends_at.asc()).first()

def apply_receipt_credit(receipt, reviewer=None, auto=False):
    owner = db.session.get(Admin, receipt.admin_id)
    if not owner:
        return False, 'Owner not found'
    owner.credit = (owner.credit or 0) + receipt.amount
    tx_type = 'manual_receipt_auto' if auto else 'manual_receipt'
    description = f"Receipt #{receipt.id}"
    log_transaction(owner.id, receipt.amount, tx_type, description)
    receipt.status = RECEIPT_STATUS_AUTO_APPROVED if auto else RECEIPT_STATUS_APPROVED
    receipt.reviewed_at = datetime.utcnow()
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.auto_deadline = None
    receipt.rejection_reason = None
    return True, None

def rollback_receipt_credit(receipt, reviewer=None, reason=None):
    owner = db.session.get(Admin, receipt.admin_id)
    if not owner:
        return False, 'Owner not found'
    owner.credit = (owner.credit or 0) - receipt.amount
    log_transaction(owner.id, -receipt.amount, 'manual_receipt_reversal', f"Receipt #{receipt.id} rejected")
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.reviewed_at = datetime.utcnow()
    receipt.rejection_reason = reason
    return True, None

def trigger_auto_receipt_processing():
    now = datetime.utcnow()
    due_receipts = ManualReceipt.query.filter(
        ManualReceipt.status == RECEIPT_STATUS_AUTO_PENDING,
        ManualReceipt.auto_deadline.isnot(None),
        ManualReceipt.auto_deadline <= now
    ).all()
    updated = 0
    for receipt in due_receipts:
        success, err = apply_receipt_credit(receipt, reviewer=None, auto=True)
        if success:
            updated += 1
        else:
            receipt.status = RECEIPT_STATUS_PENDING
            receipt.auto_deadline = None
            receipt.rejection_reason = err
    if updated or due_receipts:
        db.session.commit()

def format_bytes(size):
    if size is None or size == 0: return "0 B"
    power = 2**10
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def format_bytes_gb_tb(size):
    """Formats bytes to GB or TB only."""
    if size is None or size == 0: return "0 GB"
    
    gb_val = size / (1024**3)
    if gb_val >= 1024:
        tb_val = gb_val / 1024
        return f"{tb_val:.2f} TB"
    else:
        return f"{gb_val:.2f} GB"

def format_remaining_days(timestamp):
    # Some code paths (e.g. cached client objects) may pass expiry as string
    # like "Unlimited" or a numeric string. Normalize to int milliseconds.
    if isinstance(timestamp, str):
        ts = timestamp.strip()
        if not ts:
            timestamp = 0
        else:
            try:
                timestamp = int(float(ts))
            except Exception:
                # Non-numeric strings (e.g. "Unlimited", "Expired ...")
                timestamp = 0

    if timestamp == 0 or timestamp is None:
        return {"text": "Unlimited", "days": -1, "type": "unlimited"}
    if timestamp < 0:
        days = abs(timestamp) // 86400000
        return {"text": f"Not started ({days} days)", "days": days, "type": "start_after_use"}
    try:
        expiry_date = datetime.fromtimestamp(timestamp/1000)
        now = datetime.now()
        
        if expiry_date < now:
            days_ago = (now - expiry_date).days
            return {"text": f"Expired ({days_ago}d ago)", "days": -days_ago, "type": "expired"}
        
        days = (expiry_date - now).days
        if days == 0: 
            # Calculate Tehran time (UTC+3:30)
            expiry_utc = datetime.utcfromtimestamp(timestamp/1000)
            expiry_tehran = expiry_utc + timedelta(hours=3, minutes=30)
            time_str = expiry_tehran.strftime('%H:%M')
            return {"text": f"Today {time_str}", "days": 0, "type": "today"}
        elif days < 7: return {"text": f"{days} days left", "days": days, "type": "soon"}
        else: return {"text": f"{days} days left", "days": days, "type": "normal"}
    except:
        return {"text": "Invalid Date", "days": 0, "type": "error"}


def get_accessible_servers(user, include_disabled=False):
    if not user:
        return []
    query = Server.query
    if not include_disabled:
        query = query.filter_by(enabled=True)
    if user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)
        if allowed_map == '*':
            return query.all()

        server_ids = set(allowed_map.keys()) | set(assignments.keys())
        if not server_ids:
            return []
        return query.filter(Server.id.in_(server_ids)).all()
    return query.all()

def extract_base_and_webpath(host_url):
    """Extract base URL and webpath from panel URL.
    Example: http://1.2.3.4:8080/webpath/ -> (http://1.2.3.4:8080, /webpath)
    """
    from urllib.parse import urlparse
    parsed = urlparse(host_url.rstrip('/'))
    base = f"{parsed.scheme}://{parsed.netloc}"
    webpath = parsed.path.rstrip('/') if parsed.path and parsed.path != '/' else ''
    return base, webpath

def get_xui_session(server):
    session_obj = requests.Session()
    try:
        base, webpath = extract_base_and_webpath(server.host)
        login_url = f"{base}{webpath}/login"
        # Keep login timeout short so refresh endpoints stay responsive.
        login_resp = session_obj.post(login_url, data={"username": server.username, "password": server.password}, verify=False, timeout=3)
        if login_resp.status_code == 200 and login_resp.json().get('success'):
            return session_obj, None
        return None, f"Login failed: {login_resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)}"

def persist_detected_panel_type(server, detected_type: str) -> bool:
    """Persist detected panel type for a Server.

    Only updates when current type is auto/unset to avoid overriding a deliberate manual choice.
    Returns True if updated.
    """
    try:
        if not server:
            return False
        detected = (detected_type or '').strip().lower()
        if not detected or detected == 'auto':
            return False
        current = (getattr(server, 'panel_type', None) or 'auto').strip().lower()
        if current not in ('', 'auto'):
            return False
        if current == detected:
            return False
        server.panel_type = detected
        db.session.commit()
        return True
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return False

def fetch_inbounds(session_obj, host, panel_type='auto'):
    base, webpath = extract_base_and_webpath(host)
    timeout_sec = 3
    normalized_type = (panel_type or 'auto').strip().lower()

    # Build a prioritized endpoint map: [(endpoint, detected_panel_type)]
    endpoints_map = []

    # If panel_type is known, try only its configured endpoint first
    panel_api = get_panel_api(normalized_type)
    if normalized_type != 'auto' and panel_api and panel_api.inbounds_list:
        endpoints_map.append((panel_api.inbounds_list, normalized_type))
    else:
        # Auto-discovery: try known panel APIs first (prefer sanaei)
        try:
            all_apis = PanelAPI.query.all()
        except Exception:
            all_apis = []

        def _api_sort_key(api: 'PanelAPI'):
            pt = (getattr(api, 'panel_type', '') or '').lower()
            if pt == 'sanaei':
                return (0, pt)
            if pt == 'alireza':
                return (1, pt)
            return (2, pt)

        for api in sorted(all_apis, key=_api_sort_key):
            ep = getattr(api, 'inbounds_list', None)
            pt = (getattr(api, 'panel_type', None) or '').strip().lower()
            if ep and pt:
                endpoints_map.append((ep, pt))

        # Hardcoded fallbacks (covers older panels / missing PanelAPI rows)
        endpoints_map.extend([
            ("/panel/api/inbounds/list", "sanaei"),
            ("/xui/API/inbounds/", "alireza"),
            ("/xui/inbound/list", "xui"),
        ])

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for ep, pt in endpoints_map:
        if not ep:
            continue
        key = (ep, pt)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((ep, pt))

    for ep, detected_type in deduped:
        try:
            url = ep if ep.startswith('http') else f"{base}{webpath}{ep}"
            ep_l = ep.lower()

            # Request strategy per panel flavor
            if '/xui/' in ep_l and 'api' in ep_l:
                resp = session_obj.get(url, verify=False, timeout=timeout_sec)
                if resp.status_code == 405:
                    resp = session_obj.post(url, verify=False, timeout=timeout_sec)
            elif '/xui/' in ep_l:
                resp = session_obj.post(url, json={"page": 1, "limit": 100}, verify=False, timeout=timeout_sec)
            else:
                resp = session_obj.get(url, verify=False, timeout=timeout_sec)

            if resp.status_code != 200:
                continue

            data = resp.json()
            if not isinstance(data, dict) or not data.get('success'):
                continue

            if 'obj' in data:
                return data['obj'], None, detected_type
            if 'data' in data:
                d = data['data']
                return (d if isinstance(d, list) else d.get('list', [])), None, detected_type
        except Exception as e:
            app.logger.debug(f"Failed inbounds endpoint {ep}: {str(e)}")
            continue

    return None, "Failed to fetch inbounds", 'auto'

def generate_client_link(client, inbound, server_host):
    """Generate share links for vmess / vless / trojan / shadowsocks."""

    def _as_json(obj, default=None):
        if default is None:
            default = {}
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, str):
            try:
                return json.loads(obj)
            except Exception:
                return default
        return default

    def _parse_host(server_host, inbound_port):
        host_value = server_host or ''
        if host_value and not host_value.startswith(('http://', 'https://')):
            host_value = f"http://{host_value}"
        parsed = urlparse(host_value)
        host = parsed.hostname or parsed.path or ''
        port_val = inbound_port or parsed.port
        return host, port_val

    def _extract_stream_parts(stream_settings):
        network = (stream_settings.get('network') or 'tcp').lower()
        security = (stream_settings.get('security') or 'none').lower()

        ws = stream_settings.get('wsSettings') or {}
        grpc = stream_settings.get('grpcSettings') or {}
        tcp = stream_settings.get('tcpSettings') or {}
        h2 = stream_settings.get('httpSettings') or {}

        path = ws.get('path') or h2.get('path') or ''
        host_header = (ws.get('headers') or {}).get('Host') or (ws.get('headers') or {}).get('host') or ''
        if not host_header:
            host_header = h2.get('host') or ''

        service_name = grpc.get('serviceName') or grpc.get('service_name') or ''
        mode = grpc.get('multiMode') and 'multi' or 'gun'

        header = (tcp.get('header') or {})
        header_type = header.get('type') or ''
        if header_type == 'http':
            hosts = header.get('request', {}).get('headers', {}).get('Host') or []
            host_header = ','.join(hosts) if isinstance(hosts, list) else hosts

        tls_settings = stream_settings.get('tlsSettings') or {}
        reality_settings = stream_settings.get('realitySettings') or {}
        sni = tls_settings.get('serverName') or (reality_settings.get('serverNames') or [None])[0]
        alpn_list = tls_settings.get('alpn') or []
        alpn = ','.join(alpn_list) if isinstance(alpn_list, list) else alpn_list

        fp = reality_settings.get('fingerprint') or stream_settings.get('fingerprint')
        pbk = reality_settings.get('publicKey')
        sid = reality_settings.get('shortId') or reality_settings.get('shortIds') or ''

        return {
            "network": network,
            "security": security,
            "path": path,
            "host_header": host_header,
            "service_name": service_name,
            "grpc_mode": mode,
            "header_type": header_type,
            "sni": sni,
            "alpn": alpn,
            "fp": fp,
            "pbk": pbk,
            "sid": sid,
        }

    try:
        protocol = (inbound.get('protocol') or '').lower()
        settings = _as_json(inbound.get('settings'))
        stream_settings = _as_json(inbound.get('streamSettings'))
        stream = _extract_stream_parts(stream_settings)

        host, port = _parse_host(server_host, inbound.get('port'))
        remark = quote(client.get('email') or inbound.get('remark') or 'client')
        uuid = client.get('id') or client.get('uuid') or client.get('password') or ''
        flow = client.get('flow') or settings.get('flow') or ''

        if protocol == 'vless':
            query = {
                "encryption": "none",
                "type": stream["network"],
                "security": None if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"],
                "alpn": stream["alpn"],
                "fp": stream["fp"],
                "pbk": stream["pbk"],
                "sid": stream["sid"],
                "flow": flow or None,
            }
            if stream["network"] == 'ws':
                query.update({"path": stream["path"], "host": stream["host_header"]})
            elif stream["network"] == 'grpc':
                query.update({"type": "grpc", "serviceName": stream["service_name"], "mode": stream["grpc_mode"]})
            elif stream["network"] == 'tcp' and stream["header_type"] == 'http':
                query.update({"type": "http", "host": stream["host_header"]})

            q = {k: v for k, v in query.items() if v not in (None, '', [])}
            return f"vless://{uuid}@{host}:{port}?{urlencode(q)}#{remark}"

        if protocol == 'vmess':
            aid = client.get('alterId', client.get('aid', 0)) or 0
            vmess_obj = {
                "v": "2",
                "ps": client.get('email') or inbound.get('remark') or host,
                "add": host,
                "port": str(port),
                "id": uuid,
                "aid": str(aid),
                "scy": "auto",
                "net": stream["network"],
                "type": stream["header_type"] or "none",
                "host": stream["host_header"],
                "path": stream["path"] if stream["network"] == 'ws' else '',
                "tls": "" if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"] or "",
                "alpn": stream["alpn"] or "",
                "fp": stream["fp"] or "",
                "pbk": stream["pbk"] or "",
                "sid": stream["sid"] or "",
                "serviceName": stream["service_name"] if stream["network"] == 'grpc' else "",
            }
            payload = base64.b64encode(json.dumps(vmess_obj, ensure_ascii=False).encode()).decode()
            return f"vmess://{payload}"

        if protocol == 'trojan':
            password = client.get('password') or uuid
            query = {
                "type": stream["network"],
                "security": None if stream["security"] == 'none' else stream["security"],
                "sni": stream["sni"],
                "alpn": stream["alpn"],
                "host": stream["host_header"],
            }
            if stream["network"] == 'ws':
                query.update({"path": stream["path"]})
            elif stream["network"] == 'grpc':
                query.update({"serviceName": stream["service_name"], "mode": stream["grpc_mode"]})
            q = {k: v for k, v in query.items() if v not in (None, '', [])}
            q_str = f"?{urlencode(q)}" if q else ''
            return f"trojan://{password}@{host}:{port}{q_str}#{remark}"

        if protocol == 'shadowsocks':
            method = settings.get('method') or client.get('method')
            password = client.get('password') or uuid
            if method and password:
                userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
                query = {}
                if stream["network"] == 'ws':
                    plugin = f"v2ray-plugin;path={stream['path'] or '/'};host={stream['host_header'] or host}"
                    if stream["security"] != 'none':
                        plugin += ";tls"
                    query["plugin"] = plugin
                elif stream["network"] == 'grpc':
                    plugin = f"grpc;serviceName={stream['service_name']}"
                    query["plugin"] = plugin
                q = f"?{urlencode(query)}" if query else ''
                return f"ss://{userinfo}@{host}:{port}{q}#{remark}"
            return None

        return None
    except Exception as exc:
        app.logger.debug(f"Link gen failed: {exc}")
        return None

def find_client(inbounds, inbound_id, email):
    for inbound in inbounds:
        if inbound.get('id') != inbound_id:
            continue
        try:
            settings = json.loads(inbound.get('settings', '{}'))
        except Exception:
            settings = {}
        for client in settings.get('clients', []):
            if client.get('email') == email:
                return client, inbound
    return None, None

def process_inbounds(inbounds, server, user, allowed_map='*', assignments=None, app_base_url=None):
    processed = []
    stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "upload_raw": 0, "download_raw": 0}
    
    assignments = assignments or {}

    owned_emails = set()
    if user.role == 'reseller':
        ownerships = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server.id).all()
        owned_emails = {o.client_email.lower() for o in ownerships if o.client_email}

    for inbound in inbounds:
        try:
            inbound_id_raw = inbound.get('id')
            try:
                inbound_id = int(inbound_id_raw)
            except (TypeError, ValueError):
                inbound_id = inbound_id_raw

            if user.role == 'reseller':
                accessible = is_inbound_accessible(server.id, inbound_id, allowed_map, assignments)
                app.logger.info(f"Reseller check: server={server.id}, inbound={inbound_id}, accessible={accessible}, allowed_map={allowed_map}, assignments={assignments}")
                if not accessible:
                    continue

            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            client_stats = inbound.get('clientStats', [])
            
            processed_clients = []
            for client in clients:
                email = client.get('email', '')
                
                if user.role == 'reseller' and email.lower() not in owned_emails:
                    continue 
                
                sub_id = client.get('subId', '')
                parsed_host = urlparse(server.host)
                hostname = parsed_host.hostname
                scheme = parsed_host.scheme
                final_port = server.sub_port if server.sub_port else parsed_host.port
                port_str = f":{final_port}" if final_port else ""
                
                sub_url = ""
                json_url = ""
                dash_sub_url = ""
                
                if sub_id or (server.panel_type == 'sanaei' and client.get('id')):
                    final_id = sub_id if sub_id else client.get('id')
                    base_sub = f"{scheme}://{hostname}{port_str}"
                    s_path = server.sub_path.strip('/')
                    j_path = server.json_path.strip('/')
                    
                    if app_base_url:
                        app_base = app_base_url
                    else:
                        try:
                            app_base = request.url_root.rstrip('/')
                        except RuntimeError:
                            app_base = "" # Fallback for background thread

                    sub_url = f"{base_sub}/{s_path}/{final_id}"
                    json_url = f"{base_sub}/{j_path}/{final_id}"
                    dash_sub_url = f"{app_base}/s/{server.id}/{final_id}"

                client_up = 0
                client_down = 0
                for stat in client_stats:
                    if stat.get('email') == email:
                        client_up = stat.get('up', 0)
                        client_down = stat.get('down', 0)
                        break

                total_bytes = client.get('totalGB', 0) or 0
                remaining_bytes = max(total_bytes - (client_up + client_down), 0) if total_bytes > 0 else None
                total_formatted = format_bytes_gb_tb(total_bytes) if total_bytes > 0 else "Unlimited"

                if total_bytes <= 0:
                    stats["unlimited_volume_clients"] += 1
                
                volume_status = ""
                if remaining_bytes is not None:
                    remaining_formatted = format_bytes_gb_tb(remaining_bytes)
                    if remaining_bytes <= 0:
                        remaining_formatted = "Suspended"
                        volume_status = "suspended"
                    elif remaining_bytes < 1073741824: # 1 GB
                        remaining_formatted = f"{remaining_formatted} Low"
                        volume_status = "low"
                else:
                    remaining_formatted = "Unlimited"
                    # Use existing purple badge style (expiry-start-after) for unlimited volume
                    volume_status = "expiry-start-after"

                expiry_raw = client.get('expiryTime', 0)
                expiry_info = format_remaining_days(expiry_raw)

                if expiry_info.get('type') == 'start_after_use':
                    stats["not_started_clients"] += 1

                if expiry_info.get('type') == 'unlimited':
                    stats["unlimited_expiry_clients"] += 1

                client_data = {
                    "email": email,
                    "id": client.get('id', ''),
                    "subId": sub_id,
                    "enable": client.get('enable', True),
                    "totalGB": total_bytes,
                    "totalGB_formatted": total_formatted,
                    "remaining_bytes": remaining_bytes if remaining_bytes is not None else -1,
                    "remaining_formatted": remaining_formatted,
                    "volume_status": volume_status,
                    "expiryTime": expiry_info['text'],
                    "expiryTimestamp": expiry_raw,
                    "expiryType": expiry_info['type'],
                    "up": client_up,
                    "down": client_down,
                    "up_formatted": format_bytes(client_up),
                    "down_formatted": format_bytes(client_down),
                    "sub_url": sub_url,
                    "json_url": json_url,
                    "dash_sub_url": dash_sub_url,
                    "server_id": server.id,
                    "inbound_id": inbound.get('id'),
                    "link": generate_client_link(client, inbound, server.host)
                }
                processed_clients.append(client_data)
                
                if client.get('enable', True): stats["active_clients"] += 1
                else: stats["inactive_clients"] += 1
                stats["upload_raw"] += client_up
                stats["download_raw"] += client_down
            
            # استخراج network و security از settings
            streamSettings = settings.get('streamSettings', {})
            network = streamSettings.get('network', 'tcp')
            security = streamSettings.get('security', 'none')
            
            processed.append({
                "id": inbound.get('id'),
                "remark": inbound.get('remark', ''),
                "port": inbound.get('port', ''),
                "protocol": inbound.get('protocol', ''),
                "network": network,
                "security": security,
                "clients": processed_clients,
                "client_count": len(processed_clients),
                "enable": inbound.get('enable', False),
                "server_id": server.id,
                "server_name": server.name,
                "total_up": format_bytes(inbound.get('up', 0)),
                "total_down": format_bytes(inbound.get('down', 0)),
                "up_raw": inbound.get('up', 0),
                "down_raw": inbound.get('down', 0)
            })
            
            stats["total_clients"] += len(processed_clients)
            if inbound.get('enable', False): stats["active_inbounds"] += 1
            
        except Exception as e:
            continue
            
    stats["total_inbounds"] = len(processed)
    stats["total_upload"] = format_bytes(stats["upload_raw"])
    stats["total_download"] = format_bytes(stats["download_raw"])
    stats["total_traffic"] = format_bytes(stats["upload_raw"] + stats["download_raw"])
            
    return processed, stats

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'admin_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.form if request.form else request.json
        user = Admin.query.filter_by(username=data.get('username'), enabled=True).first()
        if user and user.check_password(data.get('password')):
            session.permanent = True
            session['admin_id'] = user.id
            session['admin_username'] = user.username
            session['role'] = user.role
            session['is_superadmin'] = (user.role == 'superadmin' or user.is_superadmin)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return jsonify({"success": True}) if request.is_json else redirect(url_for('dashboard'))
        app.logger.warning(f"Failed login attempt for user: {data.get('username')} from IP: {request.remote_addr}")
        return jsonify({"success": False, "error": "Invalid credentials"}) if request.is_json else render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    
    base_cost_day = get_config('cost_per_day', 0)
    base_cost_gb = get_config('cost_per_gb', 0)
    
    # Calculate user-specific costs
    user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
    user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
    
    # Get active bank cards for payment forms
    bank_cards = BankCard.query.filter_by(is_active=True).all()
        
    return render_template('dashboard.html', 
                         servers=servers, 
                         server_count=len(servers),
                         admin_username=user.username,
                         is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                         role=user.role,
                         credit=user.credit,
                         base_cost_day=user_cost_day,
                         base_cost_gb=user_cost_gb,
                         bank_cards=bank_cards)

@app.route('/servers')
@login_required
def servers_page():
    return render_template('servers.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/admins')
@login_required
def admins_page():
    if not session.get('is_superadmin'):
        return redirect(url_for('dashboard'))
    return render_template('admins.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

def fetch_worker(server_dict):
    with app.app_context():
        # Convert dict to object for compatibility with existing functions
        server_obj = SimpleNamespace(**server_dict)
        session_obj, error = get_xui_session(server_obj)
        if error:
            return server_dict['id'], None, error, 'auto'
        
        inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server_obj.host, server_obj.panel_type)
        return server_dict['id'], inbounds, fetch_error, detected_type

@app.route('/api/refresh')
@login_required
def api_refresh():
    # Make sure background threads are running (covers gunicorn/uwsgi workers)
    if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
        ensure_background_threads_started()

    force = _parse_bool(request.args.get('force'))
    wait = _parse_bool(request.args.get('wait'))
    server_id = request.args.get('server_id')
    mode = (request.args.get('mode') or 'cache').strip().lower()
    enqueue = request.args.get('enqueue')
    enqueue = _parse_bool(enqueue) if enqueue is not None else (mode in ('full', 'status'))
    wait_timeout = 2.0

    job = None
    if enqueue and mode in ('full', 'status'):
        job = enqueue_refresh_job(mode=mode, server_id=server_id, force=force)

    if wait and job:
        start = time.time()
        while (time.time() - start) < wait_timeout:
            with REFRESH_JOBS_LOCK:
                cur = REFRESH_JOBS.get(job.get('id'))
                if cur and cur.get('state') in ('done', 'error'):
                    job = cur
                    break
            time.sleep(0.15)

    data = copy.deepcopy(GLOBAL_SERVER_DATA)

    # If cache is empty and nothing is running, kick off a refresh job (non-blocking)
    if not data.get('inbounds') and not GLOBAL_SERVER_DATA.get('is_updating') and not job:
        job = enqueue_refresh_job(mode='full', server_id=server_id, force=False)
    
    if not data.get('inbounds'):
        return jsonify({
            "success": True, 
            "inbounds": [], 
            "stats": {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, 
                      "active_clients": 0, "inactive_clients": 0, "not_started_clients": 0, "unlimited_expiry_clients": 0, "unlimited_volume_clients": 0, "total_traffic": "0 B", 
                      "total_upload": "0 B", "total_download": "0 B"}, 
            "servers": [],
            "server_count": 0
            ,
            "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
            "refresh_job": _summarize_job(job)
        }), (202 if job and job.get('state') in ('queued', 'running') else 200)

    user = db.session.get(Admin, session['admin_id'])
    
    # === حالت سوپرادمین (یا ادمین معمولی غیر ریسلر) ===
    if user.role != 'reseller':
        # سوپرادمین همه چیز را می‌بیند
        return jsonify({
            "success": True, 
            "inbounds": data['inbounds'], 
            "stats": data['stats'], 
            "servers": data['servers_status'],
            "server_count": len(data['servers_status']),
            "last_update": data['last_update'],
            "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
            "refresh_job": _summarize_job(job)
        }), (202 if job and job.get('state') in ('queued', 'running') else 200)

    # === حالت ریسلر ===
    # 1. دریافت دسترسی‌های سرور و اینباند
    allowed_map, assignments = get_reseller_access_maps(user)
    
    # 2. دریافت لیست کلاینت‌های Assign شده به این ریسلر از دیتابیس
    owned_ownerships = ClientOwnership.query.filter_by(reseller_id=user.id).all()
    
    exact_matches = set()
    loose_matches = set()
    
    for o in owned_ownerships:
        c_email = o.client_email.lower() if o.client_email else ''
        sid = int(o.server_id)
        
        if o.inbound_id is not None:
            exact_matches.add((sid, int(o.inbound_id), c_email))
        else:
            loose_matches.add((sid, c_email))

    filtered_inbounds = []
    unique_server_ids = set()
    
    # متغیرهای آمار مخصوص ریسلر
    reseller_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,     # فقط کلاینت‌های Assign شده
        "active_clients": 0,    # فقط کلاینت‌های Assign شده فعال
        "inactive_clients": 0,  # فقط کلاینت‌های Assign شده غیرفعال
        "not_started_clients": 0,
        "unlimited_expiry_clients": 0,
        "unlimited_volume_clients": 0,
        "upload_raw": 0,        # فقط مصرف کلاینت‌های Assign شده
        "download_raw": 0
    }

    for inbound in data['inbounds']:
        sid = inbound['server_id']
        iid = inbound['id']
        
        # شرط ۱: دسترسی به اینباند (از طریق Allowed Server یا Assignment)
        if not is_inbound_accessible(sid, iid, allowed_map, assignments):
            continue
            
        # اینباند مجاز است
        unique_server_ids.add(sid)
        
        # برای نمایش در لیست: آمار کل اینباند را برای ریسلر صفر می‌کنیم (طبق درخواست)
        inbound['total_up'] = "---"
        inbound['total_down'] = "---"
        
        # شمارش اینباند
        reseller_stats["total_inbounds"] += 1
        if inbound.get('enable'):
            reseller_stats["active_inbounds"] += 1

        # پردازش کلاینت‌ها برای آمار دقیق و فیلتر کردن لیست نمایش
        clients_in_inbound = inbound.get('clients', [])
        filtered_clients_list = []
        
        for client in clients_in_inbound:
            c_email = client.get('email', '').lower()
            
            # چک می‌کنیم آیا این کلاینت به ریسلر Assign شده؟
            # 1. تطابق دقیق (سرور، اینباند، ایمیل)
            # 2. تطابق بدون اینباند (سرور، ایمیل) - برای رکوردهای قدیمی یا ناقص
            is_assigned = (sid, iid, c_email) in exact_matches or (sid, c_email) in loose_matches
            
            if is_assigned:
                # اضافه کردن به لیست فیلتر شده برای نمایش
                filtered_clients_list.append(client)
                
                # محاسبه آمار
                reseller_stats["total_clients"] += 1
                if client.get('enable'):
                    reseller_stats["active_clients"] += 1
                else:
                    reseller_stats["inactive_clients"] += 1

                if client.get('expiryType') == 'start_after_use':
                    reseller_stats["not_started_clients"] += 1

                if client.get('expiryType') == 'unlimited':
                    reseller_stats["unlimited_expiry_clients"] += 1

                # totalGB_formatted is already normalized in cached payload
                if (client.get('totalGB_formatted') == 'Unlimited'):
                    reseller_stats["unlimited_volume_clients"] += 1
                
                # جمع زدن ترافیک کلاینت‌های خودش
                reseller_stats["upload_raw"] += client.get('up', 0)
                reseller_stats["download_raw"] += client.get('down', 0)

        # جایگزینی لیست کلاینت‌های اینباند با لیست فیلتر شده
        inbound['clients'] = filtered_clients_list
        # آپدیت تعداد کلاینت‌های نمایش داده شده در اینباند
        inbound['client_count'] = len(filtered_clients_list)

        filtered_inbounds.append(inbound)

    # فرمت کردن آمار نهایی
    reseller_stats["total_traffic"] = format_bytes(reseller_stats["upload_raw"] + reseller_stats["download_raw"])
    reseller_stats["total_upload"] = format_bytes(reseller_stats["upload_raw"])
    reseller_stats["total_download"] = format_bytes(reseller_stats["download_raw"])
    
    # فیلتر کردن وضعیت سرورها
    filtered_servers_status = [
        s for s in data['servers_status'] 
        if s['server_id'] in unique_server_ids
    ]

    return jsonify({
        "success": True, 
        "inbounds": filtered_inbounds, 
        "stats": reseller_stats, 
        "servers": filtered_servers_status,
        "server_count": len(unique_server_ids),
        "last_update": data['last_update'],
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "refresh_job": _summarize_job(job)
    }), (202 if job and job.get('state') in ('queued', 'running') else 200)


@app.route('/api/refresh/job/<job_id>')
@login_required
def api_refresh_job(job_id):
    with REFRESH_JOBS_LOCK:
        job = REFRESH_JOBS.get(job_id)
        job_copy = copy.deepcopy(job) if job else None
    if not job_copy:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({
        "success": True,
        "job": _summarize_job(job_copy),
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "last_update": GLOBAL_SERVER_DATA.get('last_update')
    })

@app.route('/api/servers/list')
@login_required
def api_servers_list():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'panel_type': s.panel_type
    } for s in servers])

@app.route('/api/server/<int:server_id>/refresh')
@login_required
def api_refresh_single_server(server_id):
    user = db.session.get(Admin, session['admin_id'])
    server = Server.query.get_or_404(server_id)
    
    # Check access
    if user.role != 'superadmin':
        if user.allowed_servers != '*' and str(server.id) not in user.allowed_servers.split(','):
             return jsonify({"success": False, "error": "Access denied"}), 403

    # Non-blocking: optionally enqueue a refresh job and return cached data immediately.
    force = _parse_bool(request.args.get('force'))
    wait = _parse_bool(request.args.get('wait'))
    mode = (request.args.get('mode') or 'full').strip().lower()
    enqueue = request.args.get('enqueue')
    enqueue = _parse_bool(enqueue) if enqueue is not None else (mode != 'cache')

    job = None
    if enqueue and mode in ('full', 'status'):
        job = enqueue_refresh_job(mode='full', server_id=server.id, force=force)

        # Optional short wait for UI actions; cap to keep endpoint snappy.
        if wait and job:
            start = time.time()
            while (time.time() - start) < 2.0:
                with REFRESH_JOBS_LOCK:
                    cur = REFRESH_JOBS.get(job.get('id'))
                    if cur and cur.get('state') in ('done', 'error'):
                        job = cur
                        break
                time.sleep(0.15)

    # Pull this server's cached block (if present)
    cached_inbounds = []
    for inbound in (GLOBAL_SERVER_DATA.get('inbounds') or []):
        try:
            if int(inbound.get('server_id', -1)) == int(server.id):
                cached_inbounds.append(inbound)
        except Exception:
            continue

    cached_stats = None
    for st in (GLOBAL_SERVER_DATA.get('servers_status') or []):
        try:
            if int(st.get('server_id', -1)) == int(server.id):
                cached_stats = st.get('stats')
                break
        except Exception:
            continue

    global_stats = GLOBAL_SERVER_DATA.get('stats') or {}
    server_count = len(GLOBAL_SERVER_DATA.get('servers_status') or [])

    return jsonify({
        "success": True,
        "server_id": server.id,
        "server_name": server.name,
        "inbounds": cached_inbounds,
        "stats": global_stats,
        "server_stats": cached_stats or {},
        "server_count": server_count,
        "panel_type": server.panel_type,
        "last_update": GLOBAL_SERVER_DATA.get('last_update'),
        "is_updating": bool(GLOBAL_SERVER_DATA.get('is_updating')),
        "refresh_job": _summarize_job(job)
    }), (202 if job and job.get('state') in ('queued', 'running') else 200)


@app.route('/settings')
@login_required
def settings_page():
    user = db.session.get(Admin, session['admin_id'])
    if not user.is_superadmin:
        return redirect(url_for('dashboard'))
    return render_template('settings.html', 
                         current_user=user, 
                         is_superadmin=user.is_superadmin, 
                         app_version=APP_VERSION,
                         admin_username=user.username,
                         role=user.role)

@app.route('/api/clients/search')
@login_required
@limiter.limit("60 per minute")
def global_client_search():
    user = db.session.get(Admin, session['admin_id'])
    query = (request.args.get('email') or '').strip().lower()
    if not query:
        return jsonify({"success": False, "error": "Query parameter 'email' is required"}), 400

    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 5000))

    # --- اصلاح حرفه‌ای: جستجو در کش (RAM) به جای درخواست مجدد ---
    
    # اگر کش خالی است (برنامه تازه اجرا شده)، پیام مناسب بدهد
    if not GLOBAL_SERVER_DATA.get('inbounds'):
        return jsonify({"success": True, "results": [], "errors": ["System is starting up, please wait..."]})

    matches = []
    
    # دریافت دسترسی‌های کاربر برای فیلتر کردن نتایج
    accessible_servers = get_accessible_servers(user)
    accessible_server_ids = {s.id for s in accessible_servers}
    
    # تنظیمات دسترسی ریسلر
    allowed_map = '*'
    assignments = {}
    if user.role == 'reseller':
        allowed_map, assignments = get_reseller_access_maps(user)

    # جستجو در داده‌های موجود در رم
    for inbound in GLOBAL_SERVER_DATA['inbounds']:
        sid = inbound.get('server_id')
        iid = inbound.get('id')

        # 1. بررسی دسترسی به سرور
        if sid not in accessible_server_ids:
            continue

        # 2. بررسی دسترسی به اینباند (مخصوص ریسلرها)
        if user.role == 'reseller':
            if not is_inbound_accessible(sid, iid, allowed_map, assignments):
                continue

        # 3. جستجو در کلاینت‌های این اینباند
        clients = inbound.get('clients', [])
        for client in clients:
            c_email = client.get('email', '')
            if c_email and query in c_email.lower():
                # کلاینت پیدا شد
                matches.append({
                    "server_id": sid,
                    "server_name": inbound.get('server_name'),
                    # پنل تایپ را از روی سرور پیدا می‌کنیم (چون در کش اینباند نیست)
                    "panel_type": next((s.panel_type for s in accessible_servers if s.id == sid), 'auto'),
                    "inbound_id": iid,
                    "inbound": {
                        "id": iid,
                        "remark": inbound.get('remark', ''),
                        "port": inbound.get('port', ''),
                        "protocol": inbound.get('protocol', ''),
                        "enable": inbound.get('enable', False)
                    },
                    "client": client
                })

                if len(matches) >= limit:
                    break
        
        if len(matches) >= limit:
            break

    return jsonify({"success": True, "results": matches, "errors": []})

@app.route('/api/client/<int:server_id>/<int:inbound_id>/toggle', methods=['POST'])
@login_required
def toggle_client(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
        email = data.get('email')
        enable = data.get('enable', True)
        if not email:
            return jsonify({"success": False, "error": "Email required"}), 400
    except:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400
    
    price = 0
    description = f"Toggle client {email} to {enable}"

    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
        if price > user.credit:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}), 402
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": fetch_err}), 400

        persist_detected_panel_type(server, detected_type)
        target_client, _ = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404
        
        target_client['enable'] = bool(enable)
        client_identifier = target_client.get('id') or target_client.get('password') or target_client.get('email')
        
        payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [target_client]})
        }

        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_identifier,
            'client_id': client_identifier,
            'email': email
        }

        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            try:
                resp = session_obj.post(full_url, json=payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue

            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                if user.role == 'reseller' and price > 0:
                    user.credit -= price
                    log_transaction(user.id, -price, 'renew', description or f"Renew client {email}", server_id=server.id)
                    db.session.commit()
                response = {"success": True}
                if user.role == 'reseller':
                    response["remaining_credit"] = user.credit
                return jsonify(response)

            errors.append(f"{template}: {resp.status_code}")
            if resp.status_code != 404:
                break
        app.logger.warning(f"Toggle failed for {email}: {'; '.join(errors)}")
        return jsonify({"success": False, "error": "Client update endpoint returned error"}), 400
    except Exception as e:
        app.logger.error(f"Toggle error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/reset', methods=['POST'])
@login_required
def reset_client_traffic(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
    except:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    email = data.get('email')
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    try:
        volume_gb = int(data.get('volume_gb', 0) or 0)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid volume value"}), 400
    if volume_gb < 0:
        volume_gb = 0
    
    base_cost_gb = get_config('cost_per_gb', 0)
    user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
    
    charge_amount = volume_gb * user_cost_gb if volume_gb > 0 else 0

    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
        if user_cost_gb > 0 and volume_gb <= 0:
            return jsonify({"success": False, "error": "Billable volume required"}), 400
        if charge_amount > user.credit:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {charge_amount}, Available: {user.credit}"}), 402
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
        templates = collect_endpoint_templates(server.panel_type, 'client_reset_traffic', CLIENT_RESET_FALLBACKS)
        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'email': email
        }
        errors = []
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            requires_path_email = (':email' in template) or ('{email}' in template)
            payload = None if requires_path_email else {"email": email}
            try:
                if payload is None:
                    resp = session_obj.post(full_url, verify=False, timeout=10)
                else:
                    resp = session_obj.post(full_url, json=payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue

            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                if charge_amount > 0:
                    sender_card = data.get('sender_card', '') or ''
                    card_id = data.get('card_id')
                    if user.role == 'reseller':
                        user.credit -= charge_amount
                        log_transaction(user.id, -charge_amount, 'reset_traffic', "Reset traffic (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, charge_amount, 'reset_traffic', "Reset traffic (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()

                response = {"success": True}
                if user.role == 'reseller':
                    response["remaining_credit"] = user.credit
                return jsonify(response)

            errors.append(f"{template}: {resp.status_code}")
            if resp.status_code != 404:
                break

        app.logger.warning(f"Reset traffic failed for {email}: {'; '.join(errors)}")
        return jsonify({"success": False, "error": "Reset endpoint returned error"}), 400
    except Exception as e:
        app.logger.error(f"Reset error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/edit', methods=['POST'])
@login_required
def edit_client(server_id, inbound_id, email):
    user = db.session.get(Admin, session['admin_id'])
    if not user or not user.is_superadmin:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
        new_email = data.get('new_email', '').strip()
    except:
        return jsonify({"success": False, "error": "Invalid data"}), 400

    if not new_email:
        return jsonify({"success": False, "error": "New email is required"}), 400
        
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
        
    try:
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": "Failed to fetch inbounds"}), 400

        persist_detected_panel_type(server, detected_type)
            
        target_client, _ = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404
            
        # Extract ID before modification to ensure we target the correct client
        client_id = target_client.get('id', target_client.get('password', email))
        
        # Update email
        target_client['email'] = new_email
        
        update_payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [target_client]})
        }
        
        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_id,
            'client_id': client_id,
            'email': email 
        }
        
        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        success = False
        
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            try:
                resp = session_obj.post(full_url, json=update_payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue
                
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                success = True
                break
            
            errors.append(f"{template}: {resp.status_code}")
            
        if success:
            # Update ownership if exists
            ownerships = ClientOwnership.query.filter_by(server_id=server_id, client_email=email).all()
            for own in ownerships:
                own.client_email = new_email
            db.session.commit()
            
            return jsonify({"success": True})
        else:
            app.logger.warning(f"Edit client failed for {email}: {'; '.join(errors)}")
            return jsonify({"success": False, "error": "Update failed"}), 400
            
    except Exception as e:
        app.logger.error(f"Edit client error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/delete', methods=['POST'])
@login_required
def delete_client(server_id, inbound_id, email):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
            
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
        
    try:
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": "Failed to fetch inbounds"}), 400

        persist_detected_panel_type(server, detected_type)
            
        target_client, _ = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404
            
        client_id = target_client.get('id', target_client.get('password', email))
        
        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_id,
            'client_id': client_id,
            'email': email 
        }
        
        templates = collect_endpoint_templates(server.panel_type, 'client_delete', CLIENT_DELETE_FALLBACKS)
        errors = []
        success = False
        
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            try:
                resp = session_obj.post(full_url, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue
                
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                success = True
                break
            
            errors.append(f"{template}: {resp.status_code}")
            
        if success:
            # Remove ownership if exists
            ClientOwnership.query.filter_by(server_id=server_id, client_email=email).delete()
            db.session.commit()
            
            log_transaction(user.id, 0, 'delete_client', f"Deleted client {email}", server_id=server.id, client_email=email)
            
            return jsonify({"success": True})
        else:
            app.logger.warning(f"Delete client failed for {email}: {'; '.join(errors)}")
            return jsonify({"success": False, "error": "Delete failed"}), 400
            
    except Exception as e:
        app.logger.error(f"Delete client error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/renew', methods=['POST'])
@login_required
def renew_client(server_id, inbound_id, email):
    """Renew client expiry and/or volume"""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    server = Server.query.get_or_404(server_id)
    
    try:
        data = request.get_json() or {}
    except:
        return jsonify({"success": False, "error": "Invalid data"}), 400

    start_after_first_use = bool(data.get('start_after_first_use', False))
    reset_traffic = bool(data.get('reset_traffic', False))
    is_free = bool(data.get('free', False))
    mode = (data.get('mode') or 'custom').lower()
    if mode not in ('package', 'custom'):
        mode = 'custom'

    price = 0
    days_to_add = 0
    volume_gb_to_add = 0
    description = ""

    try:
        if mode == 'package':
            pkg_id = data.get('package_id')
            package = db.session.get(Package, pkg_id) if pkg_id else None
            if not package or not getattr(package, 'enabled', True):
                return jsonify({"success": False, "error": "Invalid package selected"}), 400
            days_to_add = int(package.days or 0)
            volume_gb_to_add = int(package.volume or 0)
            price = calculate_reseller_price(user, package=package)
            description = f"Renew Package: {package.name} - {email}"
            if days_to_add <= 0:
                return jsonify({"success": False, "error": "Package is misconfigured"}), 400
        else:
            days_to_add = int(data.get('days', 0))
            volume_gb_to_add = int(data.get('volume', 0))
            if volume_gb_to_add < 0:
                volume_gb_to_add = 0
            if days_to_add <= 0:
                return jsonify({"success": False, "error": "Days must be positive"}), 400
            
            base_cost_day = get_config('cost_per_day', 0)
            base_cost_gb = get_config('cost_per_gb', 0)
            
            user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
            user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
            
            price = (days_to_add * user_cost_day) + (volume_gb_to_add * user_cost_gb)
            description = f"Renew Custom: {days_to_add} Days, {volume_gb_to_add} GB - {email}"
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid data"}), 400

    if is_free:
        price = 0
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
        if price > 0 and user.credit < price:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}), 402
    
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
    
    try:
        inbounds, fetch_err, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": "Failed to fetch inbounds"}), 400

        persist_detected_panel_type(server, detected_type)
        target_client, _ = find_client(inbounds, inbound_id, email)
        if not target_client:
            return jsonify({"success": False, "error": "Client not found"}), 404
        
        # Calculate new expiry
        if start_after_first_use:
            new_expiry = -1 * (days_to_add * 86400000)
        else:
            current_expiry = target_client.get('expiryTime', 0)
            if current_expiry > 0:
                current_date = datetime.fromtimestamp(current_expiry / 1000)
                new_date = current_date + timedelta(days=days_to_add)
            else:
                new_date = datetime.now() + timedelta(days=days_to_add)
            new_expiry = int(new_date.timestamp() * 1000)
        
        # Update volume
        current_volume = target_client.get('totalGB', 0)
        
        if reset_traffic:
            target_client['up'] = 0
            target_client['down'] = 0
            # If resetting, set limit to new volume (if adding volume) or keep current (if just extending time)
            if volume_gb_to_add > 0:
                new_volume = volume_gb_to_add * 1024 * 1024 * 1024
            else:
                new_volume = current_volume
        else:
            new_volume = current_volume + (volume_gb_to_add * 1024 * 1024 * 1024) if volume_gb_to_add > 0 else current_volume
        
        # Update client
        target_client['expiryTime'] = new_expiry
        target_client['totalGB'] = new_volume
        
        client_id = target_client.get('id', target_client.get('password', email))

        update_payload = {
            "id": inbound_id,
            "settings": json.dumps({"clients": [target_client]})
        }

        replacements = {
            'id': inbound_id,
            'inbound_id': inbound_id,
            'inboundId': inbound_id,
            'clientId': client_id,
            'client_id': client_id,
            'email': email
        }

        templates = collect_endpoint_templates(server.panel_type, 'client_update', CLIENT_UPDATE_FALLBACKS)
        errors = []
        for template in templates:
            full_url = build_panel_url(server.host, template, replacements)
            if not full_url:
                continue
            try:
                resp = session_obj.post(full_url, json=update_payload, verify=False, timeout=10)
            except Exception as exc:
                errors.append(f"{template}: {exc}")
                continue
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict) and resp_json.get('success') is False:
                        errors.append(f"{template}: success false")
                        continue
                except ValueError:
                    pass
                
                # If reset_traffic was requested, we must call the specific reset endpoint
                # because updateClient usually ignores 'up'/'down' fields.
                if reset_traffic:
                    reset_templates = collect_endpoint_templates(server.panel_type, 'client_reset_traffic', CLIENT_RESET_FALLBACKS)
                    for r_template in reset_templates:
                        r_url = build_panel_url(server.host, r_template, replacements)
                        if not r_url: continue
                        
                        # Some panels need email in body, some in URL. Try both if needed.
                        requires_path_email = (':email' in r_template) or ('{email}' in r_template)
                        r_payload = None if requires_path_email else {"email": email}
                        
                        try:
                            if r_payload is None:
                                session_obj.post(r_url, verify=False, timeout=5)
                            else:
                                session_obj.post(r_url, json=r_payload, verify=False, timeout=5)
                            # We don't strictly check success here as the main update succeeded, 
                            # but we try our best to reset traffic.
                        except:
                            pass

                sender_card = data.get('sender_card', '') or ''
                card_id = data.get('card_id')
                if is_free:
                    if user.role == 'reseller':
                        log_transaction(user.id, 0, 'renew', f"User Renewal (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, 0, 'renew', f"User Renewal (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()
                elif price > 0:
                    if user.role == 'reseller':
                        user.credit -= price
                        log_transaction(user.id, -price, 'renew', "User Renewal (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                    else:
                        log_transaction(user.id, price, 'renew', "User Renewal (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
                    db.session.commit()

                return jsonify({"success": True})

            errors.append(f"{template}: {resp.status_code}")
            if resp.status_code != 404:
                break

        app.logger.warning(f"Renew failed for {email}: {'; '.join(errors)}")
        return jsonify({"success": False, "error": "Client update endpoint returned error"}), 400
    except Exception as e:
        app.logger.error(f"Renew error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/admins', methods=['GET'])
@superadmin_required
def get_admins():
    admins = Admin.query.all()
    return jsonify([a.to_dict() for a in admins])

@app.route('/api/admins', methods=['POST'])
@superadmin_required
def add_admin():
    data = request.json
    if Admin.query.filter_by(username=data['username']).first():
        return jsonify({"success": False, "error": "Username exists"}), 400
    
    new_admin = Admin(
        username=data['username'],
        role=data.get('role', 'reseller'),
        is_superadmin=(data.get('role') == 'superadmin'),
        credit=int(data.get('credit', 0)),
        allowed_servers=serialize_allowed_servers(data.get('allowed_servers', [])),
        enabled=data.get('enabled', True),
        discount_percent=int(data.get('discount_percent', 0)),
        custom_cost_per_day=int(data.get('custom_cost_per_day')) if data.get('custom_cost_per_day') is not None else None,
        custom_cost_per_gb=int(data.get('custom_cost_per_gb')) if data.get('custom_cost_per_gb') is not None else None,
        telegram_id=data.get('telegram_id')
    )
    new_admin.set_password(data['password'])
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admins/<int:admin_id>', methods=['PUT'])
@superadmin_required
def update_admin(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    data = request.json
    if data.get('password'): admin.set_password(data['password'])
    if data.get('role'):
        admin.role = data['role']
        admin.is_superadmin = (data['role'] == 'superadmin')
    if 'credit' in data: admin.credit = int(data['credit'])
    if 'allowed_servers' in data: admin.allowed_servers = serialize_allowed_servers(data['allowed_servers'])
    if 'enabled' in data: admin.enabled = data['enabled']
    if 'discount_percent' in data: admin.discount_percent = int(data['discount_percent'])
    if 'custom_cost_per_day' in data: 
        admin.custom_cost_per_day = int(data['custom_cost_per_day']) if data['custom_cost_per_day'] is not None else None
    if 'custom_cost_per_gb' in data: 
        admin.custom_cost_per_gb = int(data['custom_cost_per_gb']) if data['custom_cost_per_gb'] is not None else None
    if 'telegram_id' in data: admin.telegram_id = data['telegram_id']
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admins/<int:admin_id>', methods=['DELETE'])
@superadmin_required
def delete_admin(admin_id):
    if admin_id == session['admin_id']:
        return jsonify({"success": False, "error": "Self-delete not allowed"}), 400
    admin = Admin.query.get_or_404(admin_id)
    db.session.delete(admin)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers', methods=['GET'])
@login_required
def get_servers():
    user = db.session.get(Admin, session['admin_id'])
    if user.role == 'reseller':
        servers = get_accessible_servers(user)
    else:
        servers = Server.query.all()
    return jsonify([s.to_dict() for s in servers])

@app.route('/api/servers', methods=['POST'])
@login_required
def add_server():
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can add servers"}), 403
    
    data = request.json
    server = Server(
        name=data['name'],
        host=data['host'],
        username=data['username'],
        password=data['password'],
        panel_type=data.get('panel_type', 'auto'),
        sub_path=data.get('sub_path', '/sub/'),
        json_path=data.get('json_path', '/json/'),
        sub_port=data.get('sub_port')
    )
    db.session.add(server)
    db.session.commit()
    return jsonify({"success": True, "id": server.id})

@app.route('/api/servers/<int:server_id>', methods=['PUT'])
@login_required
def update_server(server_id):
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can update servers"}), 403
    
    server = Server.query.get_or_404(server_id)
    data = request.json
    server.name = data.get('name', server.name)
    server.host = data.get('host', server.host)
    server.username = data.get('username', server.username)
    server.password = data.get('password', server.password)
    server.panel_type = data.get('panel_type', server.panel_type)
    server.sub_path = data.get('sub_path', server.sub_path)
    server.json_path = data.get('json_path', server.json_path)
    server.sub_port = data.get('sub_port', server.sub_port)
    server.enabled = data.get('enabled', server.enabled)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    if session.get('role') == 'reseller':
        return jsonify({"success": False, "error": "Only admins can delete servers"}), 403
    
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>/test', methods=['POST'])
@login_required
def test_server_connection(server_id):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    if error:
        return jsonify({"success": False, "error": error}), 400
    return jsonify({"success": True, "panel_type": server.panel_type})

@app.route('/api/assign-client', methods=['POST'])
@superadmin_required
def assign_client():
    data = request.json
    server_id = data.get('server_id')
    email = data.get('email')
    reseller_id = data.get('reseller_id')
    inbound_id = data.get('inbound_id')
    
    existing = ClientOwnership.query.filter_by(reseller_id=reseller_id, server_id=server_id, client_email=email).first()
    if existing:
        return jsonify({"success": False, "error": "Client already assigned"}), 400
    
    ownership = ClientOwnership(
        reseller_id=reseller_id,
        server_id=server_id,
        inbound_id=inbound_id,
        client_email=email
    )
    db.session.add(ownership)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/client/qrcode', methods=['GET'])
def generate_qrcode():
    """Generate QR code from URL query parameter (GET request)"""
    link = request.args.get('link', '')
    if not link:
        return jsonify({"success": False, "error": "Link required"}), 400
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        return jsonify({"success": True, "qrcode": f"data:image/png;base64,{qr_base64}"})
    except Exception as e:
        app.logger.error(f"QR Code error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/qrcode', methods=['POST'])
@login_required
def client_qrcode():
    data = request.json
    url = data.get('url')
    if not url: return jsonify({"success": False}), 400
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        return jsonify({"success": True, "qrcode": f"data:image/png;base64,{qr_base64}"})
    except:
        return jsonify({"success": False}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/add', methods=['POST'])
@login_required
def add_client(server_id, inbound_id):
    user = db.session.get(Admin, session['admin_id'])
    server = Server.query.get_or_404(server_id)
    allowed_map, assignments = get_reseller_access_maps(user) if user.role == 'reseller' else ('*', {})
    
    data = request.json or {}
    email = data.get('email', '').strip()
    mode = data.get('mode', 'custom')
    start_after_first_use = bool(data.get('start_after_first_use', False))
    is_free = bool(data.get('free', False))
    
    if not email: return jsonify({"success": False, "error": "Email is required"})

    price = 0
    days = 0
    volume_gb = 0
    description = ""

    if mode == 'package':
        pkg_id = data.get('package_id')
        package = db.session.get(Package, pkg_id)
        if not package: return jsonify({"success": False, "error": "Invalid Package"}), 400
        
        price = calculate_reseller_price(user, package=package)
        days = package.days
        volume_gb = package.volume
        description = f"Purchase Package: {package.name} - {email}"
        
    else:
        days = int(data.get('days', 30))
        volume_gb = int(data.get('volume', 0))
        
        base_cost_day = get_config('cost_per_day', 0)
        base_cost_gb = get_config('cost_per_gb', 0)
        
        user_cost_day = calculate_reseller_price(user, base_price=base_cost_day, cost_type='day')
        user_cost_gb = calculate_reseller_price(user, base_price=base_cost_gb, cost_type='gb')
        
        price = (days * user_cost_day) + (volume_gb * user_cost_gb)
        description = f"Custom Plan: {days} Days, {volume_gb} GB - {email}"

    if is_free:
        price = 0

    if user.role == 'reseller':
        if not is_server_accessible(server_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this server is denied"}), 403
        if not is_inbound_accessible(server_id, inbound_id, allowed_map, assignments):
            return jsonify({"success": False, "error": "Access to this inbound is denied"}), 403
        
        if price > 0 and user.credit < price:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}), 402

    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error})
    
    try:
        client_uuid = str(uuid.uuid4())
        client_sub_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(16))
        
        expiry_time = 0
        if start_after_first_use:
            expiry_time = -1 * (days * 86400000)
        elif days > 0:
            expiry_time = int((datetime.now() + timedelta(days=days)).timestamp() * 1000)
            
        new_client = {
            "id": client_uuid,
            "email": email,
            "enable": True,
            "expiryTime": expiry_time,
            "totalGB": volume_gb * 1024 * 1024 * 1024 if volume_gb > 0 else 0,
            "subId": client_sub_id,
            "limitIp": 0,
            "flow": "",
            "tgId": "",
            "reset": 0
        }
        
        base, webpath = extract_base_and_webpath(server.host)
        if server.panel_type == 'alireza':
             get_url = f"{base}{webpath}/xui/inbound/get/{inbound_id}"
        else:
             get_url = f"{base}{webpath}/panel/api/inbounds/get/{inbound_id}"
             
        get_resp = session_obj.get(get_url, verify=False, timeout=10)
        if get_resp.status_code != 200: raise Exception("Failed to fetch inbound data from panel")
        
        inbound_data = get_resp.json().get('obj', get_resp.json().get('data', {}))
        if not inbound_data: raise Exception("Empty inbound data")

        settings = json.loads(inbound_data['settings'])
        
        for c in settings['clients']:
            if c['email'] == email: return jsonify({"success": False, "error": f"Email '{email}' already exists on server"})
            
        settings['clients'].append(new_client)
        
        update_data = inbound_data.copy()
        update_data['settings'] = json.dumps(settings)
        
        if server.panel_type == 'alireza':
            up_url = f"{base}{webpath}/xui/inbound/update/{inbound_id}"
        else:
            up_url = f"{base}{webpath}/panel/api/inbounds/update/{inbound_id}"
            
        up_resp = session_obj.post(up_url, json=update_data, verify=False, timeout=10)
        
        if up_resp.status_code == 200 and up_resp.json().get('success'):

            sender_card = data.get('sender_card', '') or ''
            card_id = data.get('card_id')
            if is_free:
                if user.role == 'reseller':
                    log_transaction(user.id, 0, 'purchase', f"Add User (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, 0, 'purchase', f"Add User (Free) - {description}", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
            elif price > 0:
                if user.role == 'reseller':
                    user.credit -= price
                    log_transaction(user.id, -price, 'purchase', "Add User (Credit Usage)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='usage', client_email=email)
                else:
                    log_transaction(user.id, price, 'purchase', "Add User (Income)", server_id=server.id, sender_card=sender_card, card_id=card_id, category='income', client_email=email)
            
            ownership = ClientOwnership(
                reseller_id=user.id,
                server_id=server.id,
                inbound_id=inbound_id,
                client_email=email,
                client_uuid=client_uuid,
                price=price
            )
            db.session.add(ownership)
            db.session.commit()
            
            # Generate Links for Response
            parsed_host = urlparse(server.host)
            hostname = parsed_host.hostname
            scheme = parsed_host.scheme
            final_port = server.sub_port if server.sub_port else parsed_host.port
            port_str = f":{final_port}" if final_port else ""
            
            base_sub = f"{scheme}://{hostname}{port_str}"
            s_path = server.sub_path.strip('/')
            final_id = client_sub_id if client_sub_id else client_uuid
            
            sub_url = f"{base_sub}/{s_path}/{final_id}"
            app_base = request.url_root.rstrip('/')
            dash_sub_url = f"{app_base}/s/{server.id}/{final_id}"
            
            direct_link = generate_client_link(new_client, inbound_data, server.host)

            return jsonify({
                "success": True,
                "client": {
                    "email": email,
                    "protocol": inbound_data.get('protocol', 'vless'),
                    "volume": volume_gb,
                    "days": days,
                    "sub_link": sub_url,
                    "direct_link": direct_link,
                    "dashboard_link": dash_sub_url
                }
            })
        else:
            msg = up_resp.json().get('msg', 'Unknown error') if up_resp.content else 'Panel update failed'
            return jsonify({"success": False, "error": f"Panel Error: {msg}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/packages', methods=['GET'])
@login_required
def get_packages():
    user = db.session.get(Admin, session['admin_id'])
    packages = Package.query.filter_by(enabled=True).all()
    
    result = []
    for p in packages:
        p_dict = p.to_dict()
        # Calculate price for this user
        p_dict['price'] = calculate_reseller_price(user, package=p)
        result.append(p_dict)
        
    return jsonify(result)

@app.route('/admin/packages', methods=['POST'])
@superadmin_required
def create_package():
    data = request.json
    package = Package(
        name=data.get('name'),
        days=int(data.get('days')),
        volume=int(data.get('volume')),
        price=int(data.get('price')),
        reseller_price=int(data.get('reseller_price')) if data.get('reseller_price') is not None else None,
        enabled=data.get('enabled', True)
    )
    db.session.add(package)
    db.session.commit()
    return jsonify({"success": True, "id": package.id})

@app.route('/admin/packages/<int:package_id>', methods=['PUT'])
@superadmin_required
def update_package(package_id):
    package = Package.query.get_or_404(package_id)
    data = request.json or {}
    if 'name' in data:
        package.name = data['name']
    if 'days' in data:
        package.days = int(data['days'])
    if 'volume' in data:
        package.volume = int(data['volume'])
    if 'price' in data:
        package.price = int(data['price'])
    if 'reseller_price' in data:
        package.reseller_price = int(data['reseller_price']) if data['reseller_price'] is not None else None
    if 'enabled' in data:
        package.enabled = bool(data['enabled'])
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/packages/<int:package_id>', methods=['DELETE'])
@superadmin_required
def delete_package(package_id):
    package = Package.query.get_or_404(package_id)
    db.session.delete(package)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/config', methods=['POST'])
@superadmin_required
def update_config():
    data = request.json
    for key, value in data.items():
        config = db.session.get(SystemConfig, key)
        if config:
            config.value = str(value)
        else:
            db.session.add(SystemConfig(key=key, value=str(value)))
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/charge', methods=['POST'])
@superadmin_required
def charge_admin():
    data = request.json
    admin_id = int(data.get('admin_id'))
    amount = int(data.get('amount'))
    description = data.get('description', 'Manual charge')
    
    admin = Admin.query.get_or_404(admin_id)
    admin.credit += amount
    
    transaction_type = 'deposit' if amount >= 0 else 'manual_debit'
    # Set category to 'income' for deposits (positive) so it counts in stats, 'expense' for debits (negative)
    category = 'income' if amount >= 0 else 'expense'

    transaction = Transaction(
        admin_id=admin_id,
        amount=amount,
        type=transaction_type,
        description=description,
        category=category
    )
    db.session.add(transaction)
    db.session.commit()
    return jsonify({"success": True, "new_credit": admin.credit})

@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    try:
        user = db.session.get(Admin, session['admin_id'])
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401

        query = Transaction.query.join(Admin)

        type_filter = (request.args.get('type') or '').strip()
        direction_filter = (request.args.get('direction') or '').strip()

        if user.role == 'reseller':
            query = query.filter(Transaction.admin_id == user.id)
        else:
            target_user_id = request.args.get('user_id', type=int)
            if target_user_id:
                query = query.filter(Transaction.admin_id == target_user_id)

        # Filter by Server (using new column)
        server_filter = request.args.get('server_id', type=int)
        if server_filter:
            accessible_ids = {s.id for s in get_accessible_servers(user, include_disabled=True)}
            if user.role == 'reseller' and server_filter not in accessible_ids:
                return jsonify({"success": False, "error": "Access denied to requested server"}), 403
            query = query.filter(Transaction.server_id == server_filter)

        search_term = (request.args.get('search') or '').strip()
        if search_term:
            pattern = f"%{search_term}%"
            query = query.filter(or_(
                Transaction.description.ilike(pattern),
                Transaction.type.ilike(pattern),
                Admin.username.ilike(pattern)
            ))

        if direction_filter == 'income':
            query = query.filter(Transaction.amount > 0)
        elif direction_filter == 'expense':
            query = query.filter(Transaction.amount < 0)

        if type_filter:
            query = query.filter(Transaction.type == type_filter)

        start_dt = parse_jalali_date(request.args.get('start_date'), end_of_day=False)
        if start_dt:
            query = query.filter(Transaction.created_at >= start_dt)

        end_dt = parse_jalali_date(request.args.get('end_date'), end_of_day=True)
        if end_dt:
            query = query.filter(Transaction.created_at <= end_dt)

        # ...existing code...
        # (rest of the function remains unchanged)
        # ...existing code...
    except Exception as ex:
        import traceback
        return jsonify({"success": False, "error": str(ex), "trace": traceback.format_exc()}), 500

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 20, type=int)
    per_page = max(1, min(per_page, 100))

    pagination = query.order_by(Transaction.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    transactions = pagination.items

    # Fallback logic for old transactions (missing server_id)
    transaction_emails = {}
    email_pairs = set()
    for tx in transactions:
        if not tx.server_id:
            email = extract_email_from_description(tx.description)
            if email:
                transaction_emails[tx.id] = email
                email_pairs.add((tx.admin_id, email))

    ownership_map = {}
    if email_pairs:
        reseller_ids = {pair[0] for pair in email_pairs}
        email_values = {pair[1] for pair in email_pairs}
        if reseller_ids and email_values:
            ownerships = ClientOwnership.query.filter(
                ClientOwnership.reseller_id.in_(list(reseller_ids)),
                func.lower(ClientOwnership.client_email).in_(list(email_values))
            ).all()
            for ownership in ownerships:
                key = (ownership.reseller_id, (ownership.client_email or '').lower())
                existing = ownership_map.get(key)
                current_created = ownership.created_at or datetime.min
                existing_created = existing.created_at if existing and existing.created_at else datetime.min
                if not existing or current_created >= existing_created:
                    ownership_map[key] = ownership

    payload = []
    for tx in transactions:
        tx_data = tx.to_dict()
        
        # If server_id was missing, try to fill it from ownership map
        if not tx_data.get('server'):
            email = transaction_emails.get(tx.id)
            if email:
                tx_data['client_email'] = email
                ownership = ownership_map.get((tx.admin_id, email))
                if ownership and ownership.server:
                    tx_data['server_id'] = ownership.server.id
                    tx_data['server'] = {
                        'id': ownership.server.id,
                        'name': ownership.server.name
                    }

        payload.append(tx_data)

    return jsonify({
        'transactions': payload,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page,
        'per_page': per_page
    })


def _truncate_text(value: str, max_len: int) -> str:
    if value is None:
        return ''
    s = str(value)
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 1)] + '…'


def _build_tx_edit_audit(editor_username: str, at_jalali: str, old_amount: int, old_type: str, old_category: str, old_desc: str, new_amount: int, new_type: str, new_category: str, new_desc: str) -> str:
    # Keep it compact (Transaction.description is VARCHAR(255))
    editor = editor_username or 'unknown'
    when = at_jalali or ''
    base = f"Edited by {editor} at {when}: {old_amount}->{new_amount}, {old_type}->{new_type}, {old_category}->{new_category}. "
    # Allocate remaining space for desc fragments
    remaining = 255 - len(base) - len("Was:  | Now: ")
    if remaining < 0:
        return _truncate_text(base, 255)
    half = max(0, remaining // 2)
    was_part = _truncate_text(old_desc or '', half)
    now_part = _truncate_text(new_desc or '', remaining - len(was_part))
    final = f"{base}Was: {was_part} | Now: {now_part}".strip()
    return _truncate_text(final, 255)


def _build_tx_delete_audit(deleter_username: str, at_jalali: str, deleted_tx_id: int, deleted_admin_username: str, deleted_amount: int, deleted_type: str) -> str:
    deleter = deleter_username or 'unknown'
    when = at_jalali or ''
    admin_u = deleted_admin_username or 'unknown'
    base = f"Deleted by {deleter} at {when}: tx#{deleted_tx_id} ({admin_u}) {deleted_amount} {deleted_type}."
    return _truncate_text(base, 255)


@app.route('/api/transactions/<int:tx_id>', methods=['PUT'])
@superadmin_required
def update_transaction(tx_id):
    editor = db.session.get(Admin, session.get('admin_id'))
    tx = Transaction.query.get_or_404(tx_id)

    try:
        data = request.get_json() or {}
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Snapshot for audit
    old_amount = tx.amount
    old_type = tx.type or ''
    old_category = tx.category or ''
    old_desc = tx.description or ''

    # Determine direction
    is_expense = None
    if 'is_expense' in data:
        is_expense = bool(data.get('is_expense'))

    # Amount (UI sends positive digits; we apply sign based on direction)
    parsed_amount = None
    if 'amount' in data:
        parsed_amount = parse_amount_to_int(data.get('amount'))
        if parsed_amount is None or int(parsed_amount) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400

    if is_expense is None:
        # infer from existing
        is_expense = (tx.amount or 0) < 0 or (tx.category == 'expense')

    if parsed_amount is not None:
        tx.amount = -abs(int(parsed_amount)) if is_expense else abs(int(parsed_amount))

    # Category
    tx.category = 'expense' if is_expense else 'income'

    # Type
    new_type = (data.get('cost_type') or data.get('type') or tx.type or '').strip() or None
    if new_type is not None:
        tx.type = new_type

    # Common fields
    if 'server_id' in data:
        tx.server_id = data.get('server_id') or None
    if 'card_id' in data:
        tx.card_id = data.get('card_id') or None
    if 'sender_card' in data:
        tx.sender_card = (data.get('sender_card') or '').strip() or None
    if 'sender_name' in data:
        tx.sender_name = (data.get('sender_name') or '').strip() or None
    if 'client_email' in data:
        tx.client_email = (data.get('client_email') or '').strip() or None

    # Date/time (Jalali + Tehran)
    if 'payment_date' in data or 'payment_time' in data:
        date_part = (data.get('payment_date') or '').strip() or None
        time_part = (data.get('payment_time') or '').strip() or None
        combined = None
        if date_part and time_part:
            combined = f"{date_part} {time_part}"
        elif date_part:
            combined = date_part
        if combined:
            dt = parse_jalali_date(combined, end_of_day=False)
            if dt:
                tx.created_at = dt

    # Description update + audit
    new_desc = old_desc
    if 'description' in data:
        new_desc = (data.get('description') or '').strip()

    audit_desc = _build_tx_edit_audit(
        editor.username if editor else 'unknown',
        format_jalali(datetime.utcnow()) or '',
        old_amount,
        old_type,
        old_category,
        old_desc,
        tx.amount,
        (tx.type or ''),
        (tx.category or ''),
        new_desc,
    )
    tx.description = audit_desc

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "error": "Failed to update transaction"}), 500

    return jsonify({"success": True, "transaction": tx.to_dict()})


@app.route('/api/transactions/<int:tx_id>', methods=['DELETE'])
@superadmin_required
def delete_transaction(tx_id):
    deleter = db.session.get(Admin, session.get('admin_id'))
    tx = Transaction.query.get_or_404(tx_id)

    # Create an audit log entry that remains visible in /transactions
    try:
        deleted_admin_username = None
        if hasattr(tx, 'admin') and tx.admin:
            deleted_admin_username = tx.admin.username
        else:
            admin_obj = db.session.get(Admin, tx.admin_id)
            deleted_admin_username = admin_obj.username if admin_obj else None

        audit_desc = _build_tx_delete_audit(
            deleter.username if deleter else 'unknown',
            format_jalali(datetime.utcnow()) or '',
            tx.id,
            deleted_admin_username,
            int(tx.amount or 0),
            (tx.type or ''),
        )

        audit_tx = Transaction(
            admin_id=deleter.id if deleter else tx.admin_id,
            amount=0,
            type='audit',
            category='usage',
            description=audit_desc,
            created_at=datetime.utcnow(),
        )
        db.session.add(audit_tx)
    except Exception:
        # If audit creation fails, continue with delete (avoid blocking admin cleanup)
        pass

    db.session.delete(tx)
    db.session.commit()
    return jsonify({"success": True})


# ==================== FINANCE OVERVIEW ====================

@app.route('/finance')
@login_required
def finance_page():
    user = db.session.get(Admin, session['admin_id'])
    cards = BankCard.query.filter_by(is_active=True).all()
    servers = Server.query.order_by(Server.name).all()
    
    # Always show user column, but for reseller only their own username
    admin_options = []
    is_superadmin_view = (user.role == 'superadmin')
    if is_superadmin_view:
        admin_options = Admin.query.order_by(Admin.username).all()
    else:
        admin_options = [user]
    return render_template('finance.html', 
                           cards=cards, 
                           is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                           admin_username=user.username,
                           role=user.role,
                           wallet_credit=user.credit,
                           admin_options=admin_options,
                           servers=servers)


@app.route('/api/payments', methods=['GET'])
@login_required
def get_payments():
    """Get payment transactions (transactions that have card info)"""
    try:
        user = db.session.get(Admin, session['admin_id'])
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        type_filter = (request.args.get('type') or '').strip()
        direction_filter = (request.args.get('direction') or '').strip()

        # Payments
        payment_query = Payment.query
        if user.role == 'reseller':
            payment_query = payment_query.filter(Payment.admin_id == user.id)
        else:
            target_user_id = request.args.get('user_id', type=int)
            if target_user_id:
                payment_query = payment_query.filter(Payment.admin_id == target_user_id)
        card_id = request.args.get('card_id', type=int)
        if card_id:
            payment_query = payment_query.filter(Payment.card_id == card_id)
        search_term = (request.args.get('search') or '').strip()
        if search_term:
            pattern = f"%{search_term}%"
            payment_query = payment_query.filter(or_(
                Payment.description.ilike(pattern),
                Payment.sender_card.ilike(pattern),
                Payment.sender_name.ilike(pattern),
                func.lower(Payment.client_email).ilike(pattern)
            ))
        start_dt = parse_jalali_date(request.args.get('start_date'), end_of_day=False)
        if start_dt:
            payment_query = payment_query.filter(Payment.payment_date >= start_dt)
        end_dt = parse_jalali_date(request.args.get('end_date'), end_of_day=True)
        if end_dt:
            payment_query = payment_query.filter(Payment.payment_date <= end_dt)
        payments_list = []
        if direction_filter != 'expense' and (not type_filter or type_filter == 'payment'):
            payments_list = payment_query.order_by(Payment.payment_date.desc()).all()

        # ...existing code...
        # (rest of the function remains unchanged)
        # ...existing code...
    except Exception as ex:
        import traceback
        return jsonify({"success": False, "error": str(ex), "trace": traceback.format_exc()}), 500
    tx_query = Transaction.query
    if user.role == 'reseller':
        tx_query = tx_query.filter(Transaction.admin_id == user.id)
    else:
        target_user_id = request.args.get('user_id', type=int)
        if target_user_id:
            tx_query = tx_query.filter(Transaction.admin_id == target_user_id)
    if card_id:
        tx_query = tx_query.filter(Transaction.card_id == card_id)
    if search_term:
        pattern = f"%{search_term}%"
        tx_query = tx_query.filter(or_(
            Transaction.description.ilike(pattern),
            Transaction.sender_card.ilike(pattern),
            Transaction.type.ilike(pattern)
        ))

    # Exclude system/audit rows from Finance overview list
    tx_query = tx_query.filter(Transaction.type != 'audit')

    if direction_filter == 'income':
        tx_query = tx_query.filter(Transaction.amount > 0)
    elif direction_filter == 'expense':
        tx_query = tx_query.filter(Transaction.amount < 0)

    if type_filter and type_filter not in ('payment', 'receipt'):
        tx_query = tx_query.filter(Transaction.type == type_filter)
    elif type_filter in ('payment', 'receipt'):
        tx_query = tx_query.filter(text('1=0'))
    if start_dt:
        tx_query = tx_query.filter(Transaction.created_at >= start_dt)
    if end_dt:
        tx_query = tx_query.filter(Transaction.created_at <= end_dt)
    transactions_list = tx_query.order_by(Transaction.created_at.desc()).all()

    # ManualReceipts
    receipt_query = ManualReceipt.query
    if user.role == 'reseller':
        receipt_query = receipt_query.filter(ManualReceipt.admin_id == user.id)
    else:
        target_user_id = request.args.get('user_id', type=int)
        if target_user_id:
            receipt_query = receipt_query.filter(ManualReceipt.admin_id == target_user_id)
    if card_id:
        receipt_query = receipt_query.filter(ManualReceipt.card_id == card_id)
    if search_term:
        pattern = f"%{search_term}%"
        receipt_query = receipt_query.filter(or_(
            ManualReceipt.reference_code.ilike(pattern),
            ManualReceipt.notes.ilike(pattern)
        ))
    if start_dt:
        receipt_query = receipt_query.filter(ManualReceipt.deposit_at >= start_dt)
    if end_dt:
        receipt_query = receipt_query.filter(ManualReceipt.deposit_at <= end_dt)
    receipts_list = []
    if direction_filter != 'expense' and (not type_filter or type_filter == 'receipt'):
        receipts_list = receipt_query.order_by(ManualReceipt.deposit_at.desc()).all()

    # Map payments
    mapped_payments = []
    for p in payments_list:
        d = p.to_dict()
        d['type'] = 'payment'
        mapped_payments.append(d)

    # Map transactions
    mapped_transactions = []
    for t in transactions_list:
        admin = db.session.get(Admin, t.admin_id)
        card = db.session.get(BankCard, t.card_id) if t.card_id else None
        server = db.session.get(Server, t.server_id) if getattr(t, 'server_id', None) else None
        jalali_date = format_jalali(t.created_at) or ''
        mapped_transactions.append({
            'id': f"tx-{t.id}",
            'admin_id': t.admin_id,
            'admin': {
                'id': admin.id,
                'username': admin.username,
                'role': admin.role
            } if admin else None,
            'sender_card': t.sender_card or '',
            'sender_name': getattr(t, 'sender_name', None) or None,
            'card_id': t.card_id,
            'card': {
                'id': card.id,
                'label': card.label,
                'bank_name': card.bank_name
            } if card else None,
            'server': {
                'id': server.id,
                'name': server.name
            } if server else None,
            'amount': int(t.amount),
            'type': t.type or 'transaction',
            'description': t.description,
            'client_email': t.client_email or (t.description.split(' - ')[-1] if t.description and ' - ' in t.description else ''),
            'payment_date': t.created_at.isoformat() if t.created_at else None,
            'payment_date_jalali': jalali_date,
            'verified': True,
            'created_at': t.created_at.isoformat() if t.created_at else None,
        })

    # Map receipts
    mapped_receipts = []
    for r in receipts_list:
        d = r.to_dict()
        d['type'] = 'receipt'
        d['payment_date'] = d.get('deposit_at') or d.get('created_at')
        d['payment_date_jalali'] = ''
        if d['payment_date']:
            try:
                dt = datetime.fromisoformat(d['payment_date'])
                d['payment_date_jalali'] = format_jalali(dt)
            except:
                pass
        mapped_receipts.append(d)

    # Combine all
    combined = mapped_payments + mapped_transactions + mapped_receipts
    def get_date(item):
        date_str = item.get('payment_date') or item.get('created_at')
        if not date_str:
            return datetime.min
        try:
            return datetime.fromisoformat(date_str)
        except:
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except:
                return datetime.min
    combined.sort(key=lambda x: get_date(x), reverse=True)
    total = len(combined)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 20, type=int)
    per_page = max(1, min(per_page, 100))
    pages = (total + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    page_items = combined[start:end]
    return jsonify({
        'payments': page_items,
        'total': total,
        'pages': pages,
        'current_page': page,
        'per_page': per_page
    })


@app.route('/api/payments', methods=['POST'])
@login_required
def add_payment():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    try:
        data = request.get_json() or {}
    except Exception as ex:
        logger.exception('Invalid JSON in add_payment')
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Log incoming request for debugging
    try:
        logger.info('add_payment request by user %s: %s', user.id, json.dumps(data, ensure_ascii=False))
    except Exception:
        logger.info('add_payment request: (unserializable data)')
    
    amount_val = parse_amount_to_int(data.get('amount'))
    if not amount_val or int(amount_val) <= 0:
        return jsonify({"success": False, "error": "Amount is required and must be positive"}), 400
    
    payment_date_str = (data.get('payment_date') or '').strip() or None
    payment_time_str = (data.get('payment_time') or '').strip() or None
    combined_dt_str = None
    if payment_date_str and payment_time_str:
        combined_dt_str = f"{payment_date_str} {payment_time_str}"
    elif payment_date_str:
        combined_dt_str = payment_date_str

    # parse_jalali_date converts Tehran -> UTC; ensure we pass date+time together to avoid double shifting
    payment_date = parse_jalali_date(combined_dt_str, end_of_day=False)
    if not payment_date:
        payment_date = datetime.utcnow()
    
    # Expense flow: create a Transaction with category='expense' (amount negative)
    is_expense = bool(data.get('is_expense'))
    if is_expense:
        cost_type = (data.get('cost_type') or 'server_cost').strip()
        server_id = data.get('server_id') or None
        amount_val = -abs(int(amount_val))

        tx = Transaction(
            admin_id=user.id,
            server_id=server_id,
            card_id=data.get('card_id') or None,
            sender_card=(data.get('sender_card') or '').strip() or None,
            sender_name=(data.get('sender_name') or '').strip() or None,
            client_email=(data.get('client_email') or '').strip() or None,
            amount=amount_val,
            type=cost_type,
            description=data.get('description', '').strip() or None,
            category='expense',
            created_at=payment_date
        )
        db.session.add(tx)
        try:
            db.session.commit()
            logger.info('Expense saved as transaction id=%s admin=%s amount=%s server=%s type=%s', tx.id, tx.admin_id, tx.amount, server_id, cost_type)
        except Exception:
            logger.exception('Failed to commit expense transaction')
            db.session.rollback()
            return jsonify({"success": False, "error": "Failed to save expense"}), 500
        return jsonify({"success": True, "id": tx.id, "mode": "expense"})

    # Income (payment) flow
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    payment = Payment(
        admin_id=user.id,
        card_id=data.get('card_id') or None,
        sender_card=data.get('sender_card', '').strip() or None,
        sender_name=data.get('sender_name', '').strip() or None,
        amount=int(amount_val),
        payment_date=payment_date,
        client_email=data.get('client_email', '').strip() or None,
        description=data.get('description', '').strip() or None,
        verified=True if is_super else False
    )
    
    db.session.add(payment)
    try:
        db.session.commit()
        logger.info('Payment saved id=%s admin=%s amount=%s', payment.id, payment.admin_id, payment.amount)
    except Exception as e:
        logger.exception('Failed to commit payment')
        db.session.rollback()
        return jsonify({"success": False, "error": "Failed to save payment"}), 500
    
    return jsonify({"success": True, "payment": payment.to_dict()})


@app.route('/api/payments/<int:payment_id>', methods=['PUT'])
@login_required
def update_payment(payment_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    payment = Payment.query.get_or_404(payment_id)
    
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    # Only owner or superadmin can edit
    if payment.admin_id != user.id and not is_super:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    try:
        data = request.get_json() or {}
    except:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    # Convert payment -> expense transaction (when editing and user switches kind)
    if bool(data.get('is_expense')):
        parsed_amount = parse_amount_to_int(data.get('amount')) if 'amount' in data else payment.amount
        if parsed_amount is None or int(parsed_amount) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400

        server_id = data.get('server_id') or None
        if not server_id:
            return jsonify({"success": False, "error": "Server is required for expense"}), 400

        # Resolve date/time (Jalali + Tehran)
        resolved_dt = payment.payment_date
        if 'payment_date' in data or 'payment_time' in data:
            date_part = (data.get('payment_date') or '').strip() or None
            time_part = (data.get('payment_time') or '').strip() or None

            if not date_part and time_part and payment.payment_date:
                # derive current Jalali date part from existing UTC datetime
                try:
                    current_tehran = payment.payment_date + timedelta(hours=3, minutes=30)
                    j_current = jdatetime_class.fromgregorian(datetime=current_tehran)
                    date_part = j_current.strftime('%Y/%m/%d')
                except Exception:
                    date_part = None

            combined_dt_str = None
            if date_part and time_part:
                combined_dt_str = f"{date_part} {time_part}"
            elif date_part:
                combined_dt_str = date_part

            new_date = parse_jalali_date(combined_dt_str, end_of_day=False)
            if new_date:
                resolved_dt = new_date

        # Carry forward fields (prefer explicit updates)
        card_id = data.get('card_id') if 'card_id' in data else payment.card_id
        sender_card = (data.get('sender_card') if 'sender_card' in data else payment.sender_card) or None
        sender_name = (data.get('sender_name') if 'sender_name' in data else payment.sender_name) or None
        client_email = (data.get('client_email') if 'client_email' in data else payment.client_email) or None
        base_desc = (data.get('description') if 'description' in data else payment.description) or ''

        sender_card = (sender_card or '').strip() or None
        sender_name = (sender_name or '').strip() or None
        client_email = (client_email or '').strip() or None
        base_desc = (base_desc or '').strip()

        cost_type = (data.get('cost_type') or 'server_cost').strip() or 'server_cost'

        audit_note = _truncate_text(
            f"Converted from payment#{payment.id} by {(user.username if user else 'unknown')} at {format_jalali(datetime.utcnow()) or ''}.",
            255,
        )
        merged_desc = (f"{base_desc} {audit_note}".strip())
        merged_desc = _truncate_text(merged_desc, 255) or None

        tx = Transaction(
            admin_id=payment.admin_id,
            server_id=server_id,
            card_id=card_id or None,
            sender_card=sender_card,
            sender_name=sender_name,
            client_email=client_email,
            amount=-abs(int(parsed_amount)),
            type=cost_type,
            description=merged_desc,
            category='expense',
            created_at=resolved_dt or datetime.utcnow(),
        )

        db.session.add(tx)
        db.session.delete(payment)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "error": "Failed to convert payment to expense"}), 500

        return jsonify({
            "success": True,
            "converted": True,
            "mode": "expense",
            "transaction_id": tx.id,
            "entry_id": f"tx-{tx.id}",
        })
    
    if 'amount' in data:
        parsed = parse_amount_to_int(data.get('amount'))
        if parsed is None or int(parsed) <= 0:
            return jsonify({"success": False, "error": "Invalid amount"}), 400
        payment.amount = int(parsed)
    if 'card_id' in data:
        payment.card_id = data['card_id'] or None
    if 'sender_card' in data:
        payment.sender_card = data['sender_card'].strip() or None
    if 'sender_name' in data:
        payment.sender_name = data['sender_name'].strip() or None
    if 'client_email' in data:
        payment.client_email = data['client_email'].strip() or None
    if 'description' in data:
        payment.description = data['description'].strip() or None
    if 'verified' in data and is_super:
        payment.verified = bool(data['verified'])
    if 'payment_date' in data or 'payment_time' in data:
        date_part = (data.get('payment_date') or '').strip() or None
        time_part = (data.get('payment_time') or '').strip() or None

        if not date_part and time_part and payment.payment_date:
            # derive current Jalali date part from existing UTC datetime
            try:
                current_tehran = payment.payment_date + timedelta(hours=3, minutes=30)
                j_current = jdatetime_class.fromgregorian(datetime=current_tehran)
                date_part = j_current.strftime('%Y/%m/%d')
            except Exception:
                date_part = None

        combined_dt_str = None
        if date_part and time_part:
            combined_dt_str = f"{date_part} {time_part}"
        elif date_part:
            combined_dt_str = date_part

        new_date = parse_jalali_date(combined_dt_str, end_of_day=False)
        if new_date:
            payment.payment_date = new_date
    
    db.session.commit()
    return jsonify({"success": True, "payment": payment.to_dict()})


@app.route('/api/payments/<int:payment_id>', methods=['DELETE'])
@login_required
def delete_payment(payment_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    payment = Payment.query.get_or_404(payment_id)
    
    is_super = (user.role == 'superadmin' or user.is_superadmin)
    # Only owner or superadmin can delete
    if payment.admin_id != user.id and not is_super:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    db.session.delete(payment)
    db.session.commit()
    return jsonify({"success": True})


@app.route('/api/finance/stats', methods=['GET'])
@login_required
def get_finance_stats():
    """Get income statistics from transactions: today, this week, this month"""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401
    
    # Calculate dates based on Tehran time and Jalali calendar
    now_utc = datetime.utcnow()
    tehran_offset = timedelta(hours=3, minutes=30)
    now_tehran = now_utc + tehran_offset
    
    j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
    
    # Start of Jalali month
    j_month_start = j_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    g_month_start_tehran = j_month_start.togregorian()
    month_start = g_month_start_tehran - tehran_offset

    # Start of previous Jalali month
    try:
        prev_year = int(j_month_start.year)
        prev_month = int(j_month_start.month) - 1
        if prev_month <= 0:
            prev_month = 12
            prev_year -= 1
        j_prev_month_start = jdatetime_class(prev_year, prev_month, 1, 0, 0, 0, 0)
        g_prev_month_start_tehran = j_prev_month_start.togregorian()
        prev_month_start = g_prev_month_start_tehran - tehran_offset
        prev_month_end = month_start
    except Exception:
        prev_month_start = None
        prev_month_end = None
    
    # Start of Today (Jalali/Tehran)
    j_today_start = j_now.replace(hour=0, minute=0, second=0, microsecond=0)
    g_today_start_tehran = j_today_start.togregorian()
    today_start = g_today_start_tehran - tehran_offset

    card_id = request.args.get('card_id', type=int)
    target_user_id = request.args.get('user_id', type=int)

    excluded_types_upper = {'SERVER_COST', 'SERVER_RENEWAL', 'SERVER_TRAFFIC'}

    if user.role == 'reseller':
        # Charge: مجموع تراکنش‌های مثبت (واریزها)
        charge_query = Transaction.query.filter(
            Transaction.admin_id == user.id,
            Transaction.amount > 0,
            or_(Transaction.type.is_(None), func.upper(Transaction.type).notin_(excluded_types_upper))
        )
        usage_query = Transaction.query.filter(Transaction.admin_id == user.id, Transaction.amount < 0)
        if card_id:
            charge_query = charge_query.filter(Transaction.card_id == card_id)
            usage_query = usage_query.filter(Transaction.card_id == card_id)

        def sum_amount(q, start_time=None):
            if start_time:
                q = q.filter(Transaction.created_at >= start_time)
            return db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q.with_entities(Transaction.id))).scalar() or 0

        today_charge = sum_amount(charge_query, today_start)
        month_charge = sum_amount(charge_query, month_start)
        total_charge = sum_amount(charge_query)

        prev_month_charge = 0
        if prev_month_start and prev_month_end:
            q_prev = charge_query.filter(Transaction.created_at >= prev_month_start, Transaction.created_at < prev_month_end)
            prev_month_charge = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q_prev.with_entities(Transaction.id))).scalar() or 0

        month_usage = abs(sum_amount(usage_query, month_start))
        total_usage = abs(sum_amount(usage_query))

        prev_month_usage = 0
        if prev_month_start and prev_month_end:
            q_prev_u = usage_query.filter(Transaction.created_at >= prev_month_start, Transaction.created_at < prev_month_end)
            prev_month_usage = abs(db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(Transaction.id.in_(q_prev_u.with_entities(Transaction.id))).scalar() or 0)

        month_net = int(month_charge) - int(month_usage)
        prev_month_net = int(prev_month_charge) - int(prev_month_usage)

        def pct_change(cur, prev):
            try:
                cur = float(cur)
                prev = float(prev)
            except Exception:
                return None
            if prev == 0:
                return 0.0 if cur == 0 else None
            return ((cur - prev) / abs(prev)) * 100.0

        month_charge_pct = pct_change(month_charge, prev_month_charge)
        month_usage_pct = pct_change(month_usage, prev_month_usage)
        month_net_pct = pct_change(month_net, prev_month_net)

        remain = total_charge - total_usage

        return jsonify({
            'success': True,
            'stats': {
                'today': today_charge,
                'month': month_charge,
                'month_expense': month_usage,
                'total': remain,
                'prev_month': prev_month_charge,
                'prev_month_expense': prev_month_usage,
                'month_net': month_net,
                'prev_month_net': prev_month_net,
                'month_change_pct': month_charge_pct,
                'month_expense_change_pct': month_usage_pct,
                'month_net_change_pct': month_net_pct,
                'payment_count': charge_query.count(),
                'total_charge': total_charge,
                'total_usage': total_usage
            }
        })
    else:
        # Month income must include ALL positive entries except server cost/renewal/traffic.
        # Also include manual `Payment` records (these are separate from `Transaction`).
        tx_income_query = Transaction.query.filter(
            Transaction.amount > 0,
            or_(Transaction.type.is_(None), func.upper(Transaction.type).notin_(excluded_types_upper))
        )
        if target_user_id:
            tx_income_query = tx_income_query.filter(Transaction.admin_id == target_user_id)
        if card_id:
            tx_income_query = tx_income_query.filter(Transaction.card_id == card_id)

        pay_income_query = Payment.query.filter(Payment.amount > 0)
        if target_user_id:
            pay_income_query = pay_income_query.filter(Payment.admin_id == target_user_id)
        if card_id:
            pay_income_query = pay_income_query.filter(Payment.card_id == card_id)

        def sum_tx_income(start_time=None, end_time=None):
            q = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
                Transaction.id.in_(tx_income_query.with_entities(Transaction.id))
            )
            if start_time:
                q = q.filter(Transaction.created_at >= start_time)
            if end_time:
                q = q.filter(Transaction.created_at < end_time)
            return q.scalar() or 0

        def sum_pay_income(start_time=None, end_time=None):
            q = db.session.query(func.coalesce(func.sum(Payment.amount), 0)).filter(
                Payment.id.in_(pay_income_query.with_entities(Payment.id))
            )
            if start_time:
                q = q.filter(Payment.payment_date >= start_time)
            if end_time:
                q = q.filter(Payment.payment_date < end_time)
            return q.scalar() or 0

        today_income = sum_tx_income(today_start) + sum_pay_income(today_start)
        month_income = sum_tx_income(month_start) + sum_pay_income(month_start)
        total_income = sum_tx_income() + sum_pay_income()

        prev_month_income = 0
        if prev_month_start and prev_month_end:
            prev_month_income = (
                sum_tx_income(prev_month_start, prev_month_end)
                + sum_pay_income(prev_month_start, prev_month_end)
            )

        # For net profit: get expense transactions separately
        expense_query = Transaction.query.filter(Transaction.category == 'expense')
        if target_user_id:
            expense_query = expense_query.filter(Transaction.admin_id == target_user_id)
        if card_id:
            expense_query = expense_query.filter(Transaction.card_id == card_id)

        total_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
            Transaction.id.in_(expense_query.with_entities(Transaction.id))
        ).scalar() or 0

        month_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
            Transaction.id.in_(expense_query.with_entities(Transaction.id)),
            Transaction.created_at >= month_start
        ).scalar() or 0

        prev_month_expense = 0
        if prev_month_start and prev_month_end:
            prev_month_expense = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)).filter(
                Transaction.id.in_(expense_query.with_entities(Transaction.id)),
                Transaction.created_at >= prev_month_start,
                Transaction.created_at < prev_month_end
            ).scalar() or 0

        month_cost_abs = abs(month_expense)
        prev_month_cost_abs = abs(prev_month_expense)
        month_profit = int(month_income) - int(month_cost_abs)
        prev_month_profit = int(prev_month_income) - int(prev_month_cost_abs)

        def pct_change(cur, prev):
            try:
                cur = float(cur)
                prev = float(prev)
            except Exception:
                return None
            if prev == 0:
                return 0.0 if cur == 0 else None
            return ((cur - prev) / abs(prev)) * 100.0

        month_income_pct = pct_change(month_income, prev_month_income)
        month_cost_pct = pct_change(month_cost_abs, prev_month_cost_abs)
        month_profit_pct = pct_change(month_profit, prev_month_profit)

        payment_count = tx_income_query.count() + pay_income_query.count()

        income_by_card = []
        if user.is_superadmin or user.role == 'reseller':
            card_stats = db.session.query(
                BankCard.id,
                BankCard.label,
                BankCard.bank_name,
                func.sum(Transaction.amount).label('total')
            ).join(Transaction, Transaction.card_id == BankCard.id).filter(
                Transaction.id.in_(tx_income_query.with_entities(Transaction.id)),
                Transaction.category.in_(['income', 'expense'])
            ).group_by(BankCard.id).all()

            for card_id, label, bank_name, total in card_stats:
                income_by_card.append({
                    'card_id': card_id,
                    'label': label,
                    'bank_name': bank_name,
                    'total': total or 0
                })
        return jsonify({
            'success': True,
            'stats': {
                'today': today_income,
                'month': month_income,
                'month_expense': abs(month_expense),
                'total': total_income,
                'prev_month': prev_month_income,
                'prev_month_expense': prev_month_cost_abs,
                'month_net': month_profit,
                'prev_month_net': prev_month_profit,
                'month_change_pct': month_income_pct,
                'month_expense_change_pct': month_cost_pct,
                'month_net_change_pct': month_profit_pct,
                'payment_count': payment_count,
                'by_card': income_by_card,
                'total_income': total_income,
                'total_expense': total_expense
            }
        })


@app.route('/api/finance/overview', methods=['GET'])
@login_required
def get_finance_overview():
    """Timeseries overview for income/expense/profit."""
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    requested_range = (request.args.get('range') or '30d').strip().lower()
    if requested_range not in ('12m', '30d', '7d', '24h', 'month'):
        requested_range = '30d'

    # Optional month selection (Jalali)
    selected_month = request.args.get('month', type=int)
    selected_year = request.args.get('year', type=int)
    if selected_month and 1 <= int(selected_month) <= 12:
        requested_range = 'month'

    card_id = request.args.get('card_id', type=int)
    target_user_id = request.args.get('user_id', type=int)

    tehran_offset = timedelta(hours=3, minutes=30)
    now_utc = datetime.utcnow()
    now_tehran = now_utc + tehran_offset

    def as_tehran(dt_utc):
        return (dt_utc + tehran_offset) if dt_utc else None

    labels = []
    keys = []
    start_utc = None
    end_utc = None

    excluded_types_upper = {'SERVER_COST', 'SERVER_RENEWAL', 'SERVER_TRAFFIC'}

    # Build bucket keys (chronological)
    if requested_range == '12m':
        j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
        j_year = int(j_now.year)
        j_month = int(j_now.month)

        def shift_month(year, month, delta):
            total = (year * 12 + (month - 1)) + delta
            new_year = total // 12
            new_month = (total % 12) + 1
            return new_year, new_month

        month_starts_tehran = []
        for i in range(11, -1, -1):
            y, m = shift_month(j_year, j_month, -i)
            j_start = jdatetime_class(y, m, 1, 0, 0, 0, 0)
            g_start_tehran = j_start.togregorian()
            month_starts_tehran.append(g_start_tehran)
            labels.append(f"{y:04d}/{m:02d}")
            keys.append((y, m))

        # end is start of next month
        next_y, next_m = shift_month(j_year, j_month, 1)
        j_end = jdatetime_class(next_y, next_m, 1, 0, 0, 0, 0)
        g_end_tehran = j_end.togregorian()
        start_utc = month_starts_tehran[0] - tehran_offset
        end_utc = g_end_tehran - tehran_offset
    elif requested_range in ('30d', '7d'):
        days = 30 if requested_range == '30d' else 7
        end_tehran = now_tehran
        end_tehran_floor = end_tehran.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start_tehran = end_tehran_floor - timedelta(days=days)
        start_utc = start_tehran - tehran_offset
        end_utc = end_tehran_floor - tehran_offset

        for i in range(days, 0, -1):
            day_start_tehran = end_tehran_floor - timedelta(days=i)
            # label as Jalali date
            j_label = (format_jalali(day_start_tehran) or '').strip()
            if ' ' in j_label:
                j_label = j_label.split(' ')[0]
            labels.append(j_label)
            keys.append(day_start_tehran.date())
    elif requested_range == 'month':
        # Daily buckets for a selected Jalali month (defaults to current Jalali year)
        j_now = jdatetime_class.fromgregorian(datetime=now_tehran)
        j_year = int(selected_year or j_now.year)
        j_month = int(selected_month or j_now.month)

        # Start of selected month
        j_start = jdatetime_class(j_year, j_month, 1, 0, 0, 0, 0)
        g_start_tehran = j_start.togregorian()
        start_utc = g_start_tehran - tehran_offset

        # Start of next month
        if j_month == 12:
            j_end = jdatetime_class(j_year + 1, 1, 1, 0, 0, 0, 0)
        else:
            j_end = jdatetime_class(j_year, j_month + 1, 1, 0, 0, 0, 0)
        g_end_tehran = j_end.togregorian()
        end_utc = g_end_tehran - tehran_offset

        # Number of days in this Jalali month
        try:
            days_in_month = int(j_end.togregorian().date() - j_start.togregorian().date()).days
        except Exception:
            days_in_month = 31
            if j_month > 6:
                days_in_month = 30
            if j_month == 12:
                days_in_month = 29

        for day in range(1, days_in_month + 1):
            # Use day number as label (cleaner for bar chart)
            labels.append(str(day))
            # Keys are Gregorian dates in Tehran (date-only)
            g_day_tehran = (jdatetime_class(j_year, j_month, day, 0, 0, 0, 0)).togregorian()
            keys.append(g_day_tehran.date())
    else:  # 24h
        end_tehran = now_tehran.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start_tehran = end_tehran - timedelta(hours=24)
        start_utc = start_tehran - tehran_offset
        end_utc = end_tehran - tehran_offset

        for i in range(24, 0, -1):
            hour_start_tehran = end_tehran - timedelta(hours=i)
            labels.append(hour_start_tehran.strftime('%H:00'))
            keys.append(hour_start_tehran)

    # Query ledger rows in a single window then bin in Python.
    # - Income: any positive amount EXCEPT server-cost/renewal/traffic.
    # - Expense: any negative amount (absolute).
    # Also include manual `Payment` rows as income.
    tx_query = Transaction.query
    if user.role == 'reseller':
        tx_query = tx_query.filter(Transaction.admin_id == user.id)
    else:
        if target_user_id:
            tx_query = tx_query.filter(Transaction.admin_id == target_user_id)

    if card_id:
        tx_query = tx_query.filter(Transaction.card_id == card_id)

    tx_query = tx_query.filter(Transaction.created_at >= start_utc, Transaction.created_at < end_utc)
    tx_query = tx_query.filter(Transaction.type != 'audit')

    tx_rows = tx_query.all()

    pay_query = Payment.query.filter(Payment.payment_date >= start_utc, Payment.payment_date < end_utc)
    if user.role == 'reseller':
        pay_query = pay_query.filter(Payment.admin_id == user.id)
    else:
        if target_user_id:
            pay_query = pay_query.filter(Payment.admin_id == target_user_id)
    if card_id:
        pay_query = pay_query.filter(Payment.card_id == card_id)
    pay_rows = pay_query.all()

    income_map = {k: 0 for k in keys}
    expense_map = {k: 0 for k in keys}

    def bucket_for_tehran_dt(tehran_dt):
        if requested_range == '12m':
            j_dt = jdatetime_class.fromgregorian(datetime=tehran_dt)
            return (int(j_dt.year), int(j_dt.month))
        if requested_range in ('30d', '7d', 'month'):
            return tehran_dt.date()
        return tehran_dt.replace(minute=0, second=0, microsecond=0)

    for tx in tx_rows:
        if not tx.created_at:
            continue
        tehran_dt = as_tehran(tx.created_at)
        if not tehran_dt:
            continue

        bucket_key = bucket_for_tehran_dt(tehran_dt)
        if bucket_key not in income_map:
            continue

        amount = int(tx.amount or 0)
        if amount > 0:
            tx_type = (tx.type or '')
            if tx_type and str(tx_type).upper() in excluded_types_upper:
                continue
            income_map[bucket_key] += amount
        elif amount < 0:
            expense_map[bucket_key] += abs(amount)

    for pay in pay_rows:
        if not pay.payment_date:
            continue
        tehran_dt = as_tehran(pay.payment_date)
        if not tehran_dt:
            continue

        bucket_key = bucket_for_tehran_dt(tehran_dt)
        if bucket_key not in income_map:
            continue

        amount = int(pay.amount or 0)
        if amount > 0:
            income_map[bucket_key] += amount

    income_series = [int(income_map[k] or 0) for k in keys]
    expense_series = [int(expense_map[k] or 0) for k in keys]
    profit_series = [int(i - e) for i, e in zip(income_series, expense_series)]

    return jsonify({
        'success': True,
        'range': requested_range,
        'month': int(selected_month) if selected_month else None,
        'year': int(selected_year) if selected_year else None,
        'labels': labels,
        'series': {
            'income': income_series,
            'expense': expense_series,
            'profit': profit_series
        }
    })


@app.route('/s/<int:server_id>/<sub_id>')
def client_subscription(server_id, sub_id):
    server = db.session.get(Server, server_id)
    if not server:
        return "Subscription not found", 404

    wants_html_view = str(request.args.get('view', '')).strip().lower() in ('1', 'true', 'yes')

    # Normalize subscription identifier early
    normalized_sub_id = str(sub_id).strip()
    target_client = None
    target_inbound = None
    found_in_cache = False

    # === Cache-first path: try to find client in in-memory GLOBAL_SERVER_DATA ===
    try:
        cached_inbounds = GLOBAL_SERVER_DATA.get('inbounds', []) or []
        # Filter inbounds for this server
        server_inbounds = [i for i in cached_inbounds if int(i.get('server_id', -1)) == int(server_id)]
        for inbound in server_inbounds:
            for client in inbound.get('clients', []):
                c_sub_id = str(client.get('subId') or '').strip()
                c_uuid = str(client.get('id') or '').strip()
                if normalized_sub_id and (normalized_sub_id == c_sub_id or (not c_sub_id and normalized_sub_id == c_uuid)):
                    target_client = client
                    target_inbound = inbound
                    found_in_cache = True
                    break
            if target_client:
                break
    except Exception:
        found_in_cache = False

    # === Fallback: if not found in cache, perform live fetch (legacy behavior) ===
    if not target_client:
        session_obj, login_error = get_xui_session(server)
        if login_error or not session_obj:
            app.logger.warning(f"Dash sub auth failed for server {server_id}: {login_error}")
            return "Unable to load subscription", 502

        inbounds, fetch_error, detected_type = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_error or not inbounds:
            app.logger.warning(f"Dash sub fetch failed for server {server_id}: {fetch_error}")
            return "Unable to load subscription", 502

        persist_detected_panel_type(server, detected_type)

        # Search in raw fetched inbounds (original logic)
        for inbound in inbounds:
            try:
                settings = json.loads(inbound.get('settings', '{}'))
            except Exception:
                continue
            for client in settings.get('clients', []):
                client_sub_id = str(client.get('subId') or '').strip()
                client_uuid = str(client.get('id') or '').strip()
                if normalized_sub_id and (normalized_sub_id == client_sub_id or (not client_sub_id and normalized_sub_id == client_uuid)):
                    target_client = client
                    target_inbound = inbound
                    break
            if target_client:
                break

    # (client search completed either from cache or from fetched inbounds)

    if not target_client or not target_inbound:
        return "Subscription not found", 404

    client_email = target_client.get('email') or f"user-{normalized_sub_id}"
    client_stats = target_inbound.get('clientStats') or []
    up = down = 0
    for stat in client_stats:
        if stat.get('email') == target_client.get('email'):
            up = stat.get('up', 0) or 0
            down = stat.get('down', 0) or 0
            break

    total_used = (up or 0) + (down or 0)
    try:
        total_limit = int(target_client.get('totalGB') or 0)
    except (TypeError, ValueError):
        total_limit = 0
    remaining = max(total_limit - total_used, 0) if total_limit > 0 else None
    percentage_used = round((total_used / total_limit) * 100, 2) if total_limit else 0

    # When serving from cache, `expiryTime` is already formatted text.
    expiry_raw_ms = target_client.get('expiryTimestamp', None) if found_in_cache else target_client.get('expiryTime', None)
    if expiry_raw_ms is None:
        expiry_raw_ms = target_client.get('expiryTime', 0)
    expiry_info = format_remaining_days(expiry_raw_ms)

    # Prepare fallback headers for client apps (used for both upstream-proxy and manual generation)
    expiry_time_ms = expiry_raw_ms or 0
    expiry_time_sec = int(expiry_time_ms / 1000) if expiry_time_ms and expiry_time_ms > 0 else 0
    user_info_header = f"upload={up}; download={down}; total={total_limit}; expire={expiry_time_sec}"
    fallback_headers = {
        'Subscription-Userinfo': user_info_header,
        'Profile-Update-Interval': '3600',
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Title': f"{server.name} - {client_email}"
    }

    host_value = server.host
    if host_value and not host_value.startswith(('http://', 'https://')):
        host_value = f"http://{host_value}"
    parsed_host = urlparse(host_value or '')
    hostname = parsed_host.hostname or parsed_host.path or ''
    scheme = parsed_host.scheme or 'http'
    final_port = server.sub_port if server.sub_port else parsed_host.port
    port_str = f":{final_port}" if final_port else ''
    sub_path = (server.sub_path or '/sub/').strip('/')
    base_sub = f"{scheme}://{hostname}{port_str}"
    sub_url = f"{base_sub}/{sub_path}/{normalized_sub_id}" if sub_path else f"{base_sub}/{normalized_sub_id}"

    # Forward query params (except local-only ones) to upstream
    forward_params = dict(request.args)
    forward_params.pop('view', None)
    forward_params.pop('format', None)
    upstream_sub_url = f"{sub_url}?{urlencode(forward_params)}" if forward_params else sub_url

    # Prepare User-Agent check
    user_agent = (request.headers.get('User-Agent') or '').lower()
    agent_tokens = ['v2ray', 'xray', 'streisand', 'shadowrocket', 'nekoray', 'nekobox', 'clash', 'sing-box', 'sagernet', 'v2box', 'hiddify']
    wants_b64 = request.args.get('format', '').lower() == 'b64'
    accept = (request.headers.get('Accept') or '').lower()
    accept_prefers_html = ('text/html' in accept) or ('application/xhtml+xml' in accept)
    is_client_app = wants_b64 or any(token in user_agent for token in agent_tokens) or (accept and not accept_prefers_html)

    # If it's a client app, try to proxy the subscription from the upstream X-UI panel
    if is_client_app and not wants_html_view:
        try:
            # Fetch from upstream
            resp = requests.get(upstream_sub_url, headers={'User-Agent': request.headers.get('User-Agent')}, timeout=15, verify=False)
            if resp.status_code == 200:
                # Prefer upstream headers (especially Subscription-Userinfo) so client apps show the same usage/expiry.
                upstream_headers = {}

                def pick_header(name: str):
                    return resp.headers.get(name) or resp.headers.get(name.lower())

                for k in ('Subscription-Userinfo', 'Profile-Title', 'Profile-Update-Interval', 'Content-Type', 'Content-Disposition'):
                    v = pick_header(k)
                    if v:
                        upstream_headers[k] = v

                if 'Subscription-Userinfo' not in upstream_headers:
                    upstream_headers['Subscription-Userinfo'] = fallback_headers['Subscription-Userinfo']
                if 'Profile-Title' not in upstream_headers:
                    upstream_headers['Profile-Title'] = fallback_headers['Profile-Title']
                if 'Profile-Update-Interval' not in upstream_headers:
                    upstream_headers['Profile-Update-Interval'] = fallback_headers['Profile-Update-Interval']
                if 'Content-Type' not in upstream_headers:
                    upstream_headers['Content-Type'] = fallback_headers['Content-Type']

                if wants_b64:
                    encoded = base64.b64encode(resp.content or b'').decode('utf-8')
                    upstream_headers['Content-Type'] = 'text/plain; charset=utf-8'
                    return encoded, 200, upstream_headers

                return resp.content, 200, upstream_headers
            else:
                app.logger.warning(f"Upstream sub fetch failed: {resp.status_code} for {upstream_sub_url}")
        except Exception as e:
            app.logger.error(f"Upstream sub fetch error: {e}")

    # Fallback to manual generation (or if not a client app, show the HTML page)
    configs = []
    direct_link = generate_client_link(target_client, target_inbound, server.host)
    if direct_link:
        configs.append(direct_link)

    subscription_entries = [entry for entry in configs if entry]
    if not subscription_entries:
        subscription_entries.append(sub_url)
    subscription_blob = '\n'.join(subscription_entries)
    encoded_blob = base64.b64encode((subscription_blob or '').encode('utf-8')).decode('utf-8') if subscription_blob else ''

    if encoded_blob and is_client_app and not wants_html_view:
        headers = dict(fallback_headers)
        headers['Content-Type'] = 'text/plain; charset=utf-8'
        return encoded_blob, 200, headers

    client_payload = {
        "email": client_email,
        "is_active": target_client.get('enable', True),
        "total_used": format_bytes(total_used),
        "total_limit": format_bytes(total_limit) if total_limit > 0 else "Unlimited",
        "percentage_used": percentage_used,
        "expiry": expiry_info['text'],
        "remaining": format_bytes(remaining) if remaining is not None else None,
        "subscription_url": f"{request.base_url}?format=b64",
        "configs": configs,
        "server_name": server.name
    }

    apps = SubAppConfig.query.filter_by(is_enabled=True).all()
    apps_payload = [app.to_dict() for app in apps]
    
    # Get FAQs
    faqs = FAQ.query.filter_by(is_enabled=True).all()
    faqs_payload = [faq.to_dict() for faq in faqs]
    
    # Get support info
    support_telegram = db.session.get(SystemConfig, 'support_telegram')
    support_whatsapp = db.session.get(SystemConfig, 'support_whatsapp')
    
    support_info = {
        'telegram': support_telegram.value if support_telegram else '',
        'whatsapp': support_whatsapp.value if support_whatsapp else ''
    }

    return render_template('subscription.html', client=client_payload, apps=apps_payload, faqs=faqs_payload, support=support_info)

@app.route('/sub-manager')
@superadmin_required
def sub_manager_page():
    user = db.session.get(Admin, session['admin_id'])
    
    support_telegram = db.session.get(SystemConfig, 'support_telegram')
    support_whatsapp = db.session.get(SystemConfig, 'support_whatsapp')
    
    return render_template('sub_manager.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         support_telegram=support_telegram.value if support_telegram else '',
                         support_whatsapp=support_whatsapp.value if support_whatsapp else '')

@app.route('/api/sub-apps', methods=['GET'])
def get_sub_apps():
    apps = SubAppConfig.query.all()
    return jsonify([a.to_dict() for a in apps])

@app.route('/api/sub-apps', methods=['POST'])
@superadmin_required
def create_sub_app():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    # Auto-generate app_code if not provided
    app_code = data.get('app_code')
    if not app_code:
        app_code = str(uuid.uuid4())[:8]
        
    if SubAppConfig.query.filter_by(app_code=app_code).first():
        return jsonify({'success': False, 'error': 'App code already exists'}), 400
        
    new_app = SubAppConfig(
        app_code=app_code,
        name=data.get('name'),
        os_type=data.get('os_type', 'android'),
        is_enabled=data.get('is_enabled', True),
        title_fa=data.get('title_fa'),
        description_fa=data.get('description_fa'),
        title_en=data.get('title_en'),
        description_en=data.get('description_en'),
        download_link=data.get('download_link'),
        store_link=data.get('store_link'),
        tutorial_link=data.get('tutorial_link')
    )
    
    try:
        db.session.add(new_app)
        db.session.commit()
        return jsonify({'success': True, 'app': new_app.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sub-apps/<int:app_id>', methods=['PUT'])
@superadmin_required
def update_sub_app(app_id):
    app_config = db.session.get(SubAppConfig, app_id)
    if not app_config:
        return jsonify({'success': False, 'error': 'App not found'}), 404
        
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    # Check if app_code is being changed and if it conflicts
    new_app_code = data.get('app_code')
    if new_app_code and new_app_code != app_config.app_code:
        if SubAppConfig.query.filter_by(app_code=new_app_code).first():
            return jsonify({'success': False, 'error': 'App code already exists'}), 400
        app_config.app_code = new_app_code
        
    if 'name' in data: app_config.name = data['name']
    if 'os_type' in data: app_config.os_type = data['os_type']
    if 'is_enabled' in data: app_config.is_enabled = data['is_enabled']
    if 'title_fa' in data: app_config.title_fa = data['title_fa']
    if 'description_fa' in data: app_config.description_fa = data['description_fa']
    if 'title_en' in data: app_config.title_en = data['title_en']
    if 'description_en' in data: app_config.description_en = data['description_en']
    if 'download_link' in data: app_config.download_link = data['download_link']
    if 'store_link' in data: app_config.store_link = data['store_link']
    if 'tutorial_link' in data: app_config.tutorial_link = data['tutorial_link']
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'app': app_config.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sub-apps/<int:app_id>', methods=['DELETE'])
@superadmin_required
def delete_sub_app(app_id):
    app_config = db.session.get(SubAppConfig, app_id)
    if not app_config:
        return jsonify({'success': False, 'error': 'App not found'}), 404
        
    try:
        db.session.delete(app_config)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# FAQ APIs
@app.route('/api/faqs', methods=['GET'])
def get_faqs():
    faqs = FAQ.query.order_by(FAQ.created_at.desc()).all()
    return jsonify([f.to_dict() for f in faqs])

@app.route('/api/faqs', methods=['POST'])
@superadmin_required
def create_faq():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    if not data.get('title'):
        return jsonify({'success': False, 'error': 'Title is required'}), 400
        
    new_faq = FAQ(
        title=data.get('title'),
        content=data.get('content'),
        image_url=data.get('image_url'),
        video_url=data.get('video_url'),
        platform=data.get('platform', 'android'),
        is_enabled=data.get('is_enabled', True)
    )
    
    try:
        db.session.add(new_faq)
        db.session.commit()
        return jsonify({'success': True, 'faq': new_faq.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/faqs/<int:faq_id>', methods=['PUT'])
@superadmin_required
def update_faq(faq_id):
    faq = db.session.get(FAQ, faq_id)
    if not faq:
        return jsonify({'success': False, 'error': 'FAQ not found'}), 404
        
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    if 'title' in data: faq.title = data['title']
    if 'content' in data: faq.content = data['content']
    if 'image_url' in data: faq.image_url = data['image_url']
    if 'video_url' in data: faq.video_url = data['video_url']
    if 'platform' in data: faq.platform = data['platform']
    if 'is_enabled' in data: faq.is_enabled = data['is_enabled']
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'faq': faq.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/faqs/<int:faq_id>', methods=['DELETE'])
@superadmin_required
def delete_faq(faq_id):
    faq = db.session.get(FAQ, faq_id)
    if not faq:
        return jsonify({'success': False, 'error': 'FAQ not found'}), 404
        
    try:
        db.session.delete(faq)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@superadmin_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
        
    if file:
        filename = secure_filename(f"{uuid.uuid4().hex[:8]}_{file.filename}")
        upload_folder = os.path.join(app.static_folder, 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        file.save(os.path.join(upload_folder, filename))
        return jsonify({'success': True, 'url': f'/static/uploads/{filename}'})

@app.route('/api/system-config', methods=['POST'])
@superadmin_required
def update_system_config():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
        
    try:
        for key, value in data.items():
            config = db.session.get(SystemConfig, key)
            if config:
                config.value = str(value)
            else:
                config = SystemConfig(key=key, value=str(value))
                db.session.add(config)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/packages')
@superadmin_required
def packages_page():
    cost_gb = db.session.get(SystemConfig, 'cost_per_gb')
    cost_day = db.session.get(SystemConfig, 'cost_per_day')
    
    return render_template('packages.html', 
                         base_cost_gb=int(cost_gb.value) if cost_gb else 0,
                         base_cost_day=int(cost_day.value) if cost_day else 0,
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/bank-cards')
@superadmin_required
def bank_cards_page():
    return render_template('bank_cards.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/api/bank-cards', methods=['GET'])
@login_required
def list_bank_cards():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    include_inactive = request.args.get('include_inactive', '0') in ('1', 'true', 'True')
    query = BankCard.query
    if not (user.role == 'superadmin' or user.is_superadmin):
        query = query.filter_by(is_active=True)
    elif not include_inactive:
        query = query.filter_by(is_active=True)
    cards = query.order_by(BankCard.created_at.desc()).all()
    return jsonify({'success': True, 'cards': [card.to_dict() for card in cards]})

@app.route('/api/bank-cards', methods=['POST'])
@superadmin_required
def create_bank_card():
    data = request.get_json() or {}
    label = (data.get('label') or '').strip()
    if not label:
        return jsonify({'success': False, 'error': 'Label is required'}), 400
    card = BankCard(
        label=label,
        bank_name=(data.get('bank_name') or '').strip() or None,
        owner_name=(data.get('owner_name') or '').strip() or None,
        card_number=(data.get('card_number') or '').strip() or None,
        iban=(data.get('iban') or '').strip() or None,
        account_number=(data.get('account_number') or '').strip() or None,
        notes=(data.get('notes') or '').strip() or None,
        is_active=bool(data.get('is_active', True))
    )
    db.session.add(card)
    db.session.commit()
    return jsonify({'success': True, 'card': card.to_dict()})

@app.route('/api/bank-cards/<int:card_id>', methods=['PUT'])
@superadmin_required
def update_bank_card(card_id):
    card = db.session.get(BankCard, card_id)
    if not card:
        return jsonify({'success': False, 'error': 'Card not found'}), 404
    data = request.get_json() or {}
    for field in ('label', 'bank_name', 'owner_name', 'card_number', 'iban', 'account_number', 'notes'):
        if field in data:
            value = data.get(field)
            setattr(card, field, value.strip() if isinstance(value, str) else value)
    if 'is_active' in data:
        card.is_active = bool(data.get('is_active'))
    db.session.commit()
    return jsonify({'success': True, 'card': card.to_dict()})

@app.route('/api/bank-cards/<int:card_id>', methods=['DELETE'])
@superadmin_required
def delete_bank_card(card_id):
    card = db.session.get(BankCard, card_id)
    if not card:
        return jsonify({'success': False, 'error': 'Card not found'}), 404
    db.session.delete(card)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/transactions')
@login_required
def transactions_page():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user, include_disabled=True) if user else []
    admin_options = []
    if user and (user.role == 'superadmin' or user.is_superadmin):
        admin_options = Admin.query.order_by(Admin.username.asc()).all()
    return render_template('transactions.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         servers=servers,
                         admin_options=admin_options)

@app.route('/receipts')
@login_required
def receipts_page():
    return render_template('receipts.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'),
                         current_admin_id=session.get('admin_id'))

@app.route('/api/receipts', methods=['POST'])
@login_required
def upload_receipt():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    trigger_auto_receipt_processing()

    form = request.form
    try:
        amount = int(form.get('amount', 0))
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Amount must be positive'}), 400

    card_id = form.get('card_id')
    card = None
    if card_id:
        try:
            card = db.session.get(BankCard, int(card_id))
        except (TypeError, ValueError):
            card = None
        if not card:
            return jsonify({'success': False, 'error': 'Selected card not found'}), 404
        if not card.is_active and not (user.role == 'superadmin' or user.is_superadmin):
            return jsonify({'success': False, 'error': 'Card is inactive'}), 400

    slip_file = request.files.get('file')
    if not slip_file or not slip_file.filename:
        return jsonify({'success': False, 'error': 'Receipt image is required'}), 400
    if not allowed_receipt_file(slip_file.filename):
        return jsonify({'success': False, 'error': 'Unsupported file type'}), 400
    stored_path = save_receipt_file(slip_file)
    if not stored_path:
        return jsonify({'success': False, 'error': 'Failed to store file'}), 400

    deposit_at = parse_iso_datetime(form.get('deposit_at'))
    reference_code = (form.get('reference_code') or '').strip() or None
    notes = (form.get('notes') or '').strip() or None
    currency = (form.get('currency') or 'IRT').strip().upper()
    if len(currency) > 10:
        currency = currency[:10]

    auto_window = get_active_auto_window()
    initial_status = RECEIPT_STATUS_PENDING
    auto_deadline = None
    if auto_window and (auto_window.max_amount <= 0 or amount <= auto_window.max_amount):
        initial_status = RECEIPT_STATUS_AUTO_PENDING
        auto_deadline = auto_window.ends_at

    receipt = ManualReceipt(
        admin_id=user.id,
        card_id=card.id if card else None,
        amount=amount,
        currency=currency,
        deposit_at=deposit_at,
        reference_code=reference_code,
        image_path=stored_path,
        status=initial_status,
        auto_deadline=auto_deadline,
        notes=notes
    )
    db.session.add(receipt)
    db.session.commit()

    payload = receipt.to_dict()
    payload['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    return jsonify({'success': True, 'receipt': payload})

@app.route('/api/receipts', methods=['GET'])
@login_required
def list_receipts():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    trigger_auto_receipt_processing()
    query = ManualReceipt.query.join(Admin, ManualReceipt.admin_id == Admin.id)
    if not (user.role == 'superadmin' or user.is_superadmin):
        query = query.filter(ManualReceipt.admin_id == user.id)
    else:
        admin_filter = request.args.get('user_id', type=int)
        if admin_filter:
            query = query.filter(ManualReceipt.admin_id == admin_filter)
    status_filter = request.args.get('status')
    if status_filter:
        query = query.filter(ManualReceipt.status == status_filter)
    limit = request.args.get('limit', type=int) or 200
    limit = max(1, min(limit, 1000))
    receipts = query.order_by(ManualReceipt.created_at.desc()).limit(limit).all()
    payload = []
    for receipt in receipts:
        data = receipt.to_dict()
        data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
        payload.append(data)
    return jsonify({'success': True, 'receipts': payload})

@app.route('/receipts/file/<int:receipt_id>')
@login_required
def download_receipt_file(receipt_id):
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    if receipt.admin_id != user.id and not (user.role == 'superadmin' or user.is_superadmin):
        return jsonify({'success': False, 'error': 'Forbidden'}), 403
    if not receipt.image_path:
        return jsonify({'success': False, 'error': 'File missing'}), 404
    full_path = os.path.join(app.instance_path, receipt.image_path)
    if not os.path.abspath(full_path).startswith(os.path.abspath(RECEIPTS_DIR)):
        return jsonify({'success': False, 'error': 'Invalid path'}), 403
    if not os.path.isfile(full_path):
        return jsonify({'success': False, 'error': 'File missing'}), 404
    return send_file(full_path, as_attachment=False)

@app.route('/api/receipts/<int:receipt_id>/approve', methods=['POST'])
@superadmin_required
def approve_receipt(receipt_id):
    trigger_auto_receipt_processing()
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    reviewer = db.session.get(Admin, session['admin_id'])
    allowed_states = {RECEIPT_STATUS_PENDING, RECEIPT_STATUS_AUTO_PENDING, RECEIPT_STATUS_REJECTED}
    if receipt.status not in allowed_states:
        if receipt.status in (RECEIPT_STATUS_APPROVED, RECEIPT_STATUS_AUTO_APPROVED):
            data = receipt.to_dict()
            data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
            return jsonify({'success': True, 'receipt': data})
        return jsonify({'success': False, 'error': 'Invalid receipt state'}), 400
    success, error = apply_receipt_credit(receipt, reviewer=reviewer, auto=False)
    if not success:
        return jsonify({'success': False, 'error': error}), 400
    db.session.commit()
    data = receipt.to_dict()
    data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    data['new_balance'] = receipt.admin.credit if receipt.admin else None
    return jsonify({'success': True, 'receipt': data})

@app.route('/api/receipts/<int:receipt_id>/reject', methods=['POST'])
@superadmin_required
def reject_receipt(receipt_id):
    trigger_auto_receipt_processing()
    receipt = db.session.get(ManualReceipt, receipt_id)
    if not receipt:
        return jsonify({'success': False, 'error': 'Receipt not found'}), 404
    data = request.get_json() or {}
    reason = (data.get('reason') or '').strip() or 'Rejected'
    reviewer = db.session.get(Admin, session['admin_id'])
    if receipt.status in (RECEIPT_STATUS_APPROVED, RECEIPT_STATUS_AUTO_APPROVED):
        success, error = rollback_receipt_credit(receipt, reviewer=reviewer, reason=reason)
        if not success:
            return jsonify({'success': False, 'error': error}), 400
    receipt.status = RECEIPT_STATUS_REJECTED
    receipt.reviewer_id = reviewer.id if reviewer else None
    receipt.reviewed_at = datetime.utcnow()
    receipt.rejection_reason = reason
    receipt.auto_deadline = None
    db.session.commit()
    data = receipt.to_dict()
    data['image_url'] = url_for('download_receipt_file', receipt_id=receipt.id)
    return jsonify({'success': True, 'receipt': data})

@app.route('/api/receipts/auto-windows', methods=['GET'])
@superadmin_required
def list_auto_windows():
    windows = AutoApprovalWindow.query.order_by(AutoApprovalWindow.starts_at.desc()).all()
    return jsonify({'success': True, 'windows': [w.to_dict() for w in windows]})

@app.route('/api/receipts/auto-windows', methods=['POST'])
@superadmin_required
def create_auto_window():
    data = request.get_json() or {}
    starts_at = parse_iso_datetime(data.get('starts_at')) or datetime.utcnow()
    ends_at = parse_iso_datetime(data.get('ends_at'))
    if not ends_at or ends_at <= starts_at:
        return jsonify({'success': False, 'error': 'Invalid window timeframe'}), 400
    try:
        max_amount = int(data.get('max_amount', 0) or 0)
    except (TypeError, ValueError):
        max_amount = 0
    window = AutoApprovalWindow(
        starts_at=starts_at,
        ends_at=ends_at,
        max_amount=max_amount,
        status='enabled'
    )
    db.session.add(window)
    db.session.commit()
    return jsonify({'success': True, 'window': window.to_dict()})

@app.route('/api/receipts/auto-windows/<int:window_id>', methods=['DELETE'])
@superadmin_required
def disable_auto_window(window_id):
    window = db.session.get(AutoApprovalWindow, window_id)
    if not window:
        return jsonify({'success': False, 'error': 'Window not found'}), 404
    window.status = 'disabled'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/templates', methods=['GET'])
@superadmin_required
def get_templates():
    templates = NotificationTemplate.query.order_by(NotificationTemplate.created_at.desc()).all()
    return jsonify({'success': True, 'templates': [t.to_dict() for t in templates]})

@app.route('/api/templates', methods=['POST'])
@superadmin_required
def create_template():
    data = request.get_json()
    name = data.get('name')
    content = data.get('content')
    
    if not name or not content:
        return jsonify({'success': False, 'error': 'Name and content are required'}), 400
        
    template = NotificationTemplate(name=name, content=content)
    db.session.add(template)
    db.session.commit()
    
    # If this is the first template, make it active
    if NotificationTemplate.query.count() == 1:
        template.is_active = True
        db.session.commit()
        
    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/templates/<int:id>', methods=['PUT'])
@superadmin_required
def update_template(id):
    template = db.session.get(NotificationTemplate, id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
        
    data = request.get_json()
    if 'name' in data:
        template.name = data['name']
    if 'content' in data:
        template.content = data['content']
        
    db.session.commit()
    return jsonify({'success': True, 'template': template.to_dict()})

@app.route('/api/templates/<int:id>', methods=['DELETE'])
@superadmin_required
def delete_template(id):
    template = db.session.get(NotificationTemplate, id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
        
    if template.is_active:
        return jsonify({'success': False, 'error': 'Cannot delete active template'}), 400
        
    db.session.delete(template)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/templates/<int:id>/activate', methods=['POST'])
@superadmin_required
def activate_template(id):
    template = db.session.get(NotificationTemplate, id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
        
    # Deactivate all others
    NotificationTemplate.query.update({NotificationTemplate.is_active: False})
    template.is_active = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/templates/active', methods=['GET'])
@login_required
def get_active_template():
    template = NotificationTemplate.query.filter_by(is_active=True).first()
    if not template:
        # Return default if no template exists
        default_content = """😍 سفارش جدید شما

اطلاعات سرویس
📡 پروتکل: {protocol}
🔮 نام سرویس: {service_name}
🔋حجم سرویس: {volume} گیگ
⏰ مدت سرویس: {days} روز⁮⁮ ⁮⁮

لینک های اتصال
 
🌐 subscription Direct:
{sub_link}

🌐 Account Dashboard : 
{dashboard_link}"""
        return jsonify({'success': True, 'content': default_content})
        
    return jsonify({'success': True, 'content': template.content})

@app.route('/api/backups', methods=['GET'])
@login_required
def list_backups():
    backups = []
    if os.path.exists(BACKUP_DIR):
        files = glob.glob(os.path.join(BACKUP_DIR, '*.db'))
        files.sort(key=os.path.getmtime, reverse=True)
        for f in files:
            name = os.path.basename(f)
            size = os.path.getsize(f)
            date = datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Determine type
            if name.startswith('upload_'):
                b_type = 'Uploaded'
            elif name.startswith('auto_'):
                b_type = 'Automatic'
            elif name.startswith('pre_restore_'):
                b_type = 'Safety'
            else:
                b_type = 'System'
                
            backups.append({'name': name, 'size': size, 'date': date, 'type': b_type})
    return jsonify({'success': True, 'backups': backups})

@app.route('/api/backups', methods=['POST'])
@login_required
def create_backup():
    try:
        db_path = os.path.join(app.instance_path, 'servers.db')
        if not os.path.exists(db_path):
             return jsonify({'success': False, 'error': 'Database file not found'})
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'backup_{timestamp}.db'
        dest = os.path.join(BACKUP_DIR, filename)
        
        shutil.copy2(db_path, dest)
        return jsonify({'success': True, 'message': 'Backup created', 'filename': filename})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/backups/upload', methods=['POST'])
@login_required
def upload_backup():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    if file and file.filename.endswith('.db'):
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_name = secure_filename(file.filename)
            filename = f'upload_{timestamp}_{safe_name}'
            file.save(os.path.join(BACKUP_DIR, filename))
            return jsonify({'success': True, 'message': 'Backup uploaded successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': False, 'error': 'Invalid file type. Only .db files allowed'})

@app.route('/api/settings/backup', methods=['GET'])
@login_required
def get_backup_settings():
    freq = db.session.get(SystemSetting, 'backup_frequency')
    return jsonify({
        'success': True,
        'frequency': freq.value if freq else 'disabled'
    })

@app.route('/api/settings/backup', methods=['POST'])
@login_required
def save_backup_settings():
    data = request.json
    freq_val = data.get('frequency', 'disabled')
    
    setting = db.session.get(SystemSetting, 'backup_frequency')
    if not setting:
        setting = SystemSetting(key='backup_frequency', value=freq_val)
        db.session.add(setting)
    else:
        setting.value = freq_val
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Settings saved'})

@app.route('/api/settings/ssl', methods=['GET'])
@login_required
def get_ssl_settings():
    cert = db.session.get(SystemSetting, 'ssl_cert_path')
    key = db.session.get(SystemSetting, 'ssl_key_path')
    return jsonify({
        'success': True,
        'cert_path': cert.value if cert else '',
        'key_path': key.value if key else ''
    })

@app.route('/api/settings/ssl', methods=['POST'])
@login_required
def save_ssl_settings():
    data = request.json
    cert_path = data.get('cert_path', '').strip()
    key_path = data.get('key_path', '').strip()
    
    # Save cert path
    cert_setting = db.session.get(SystemSetting, 'ssl_cert_path')
    if not cert_setting:
        cert_setting = SystemSetting(key='ssl_cert_path', value=cert_path)
        db.session.add(cert_setting)
    else:
        cert_setting.value = cert_path
        
    # Save key path
    key_setting = db.session.get(SystemSetting, 'ssl_key_path')
    if not key_setting:
        key_setting = SystemSetting(key='ssl_key_path', value=key_path)
        db.session.add(key_setting)
    else:
        key_setting.value = key_path
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'SSL settings saved'})

@app.route('/api/settings/session', methods=['GET'])
@login_required
def get_session_settings():
    setting = db.session.get(SystemSetting, 'session_timeout_hours')
    return jsonify({
        'success': True,
        'timeout_hours': int(setting.value) if setting else 168 # Default 7 days = 168 hours
    })

@app.route('/api/settings/session', methods=['POST'])
@login_required
def save_session_settings():
    data = request.json
    try:
        hours = int(data.get('timeout_hours', 168))
        if hours < 1:
            return jsonify({'success': False, 'message': 'Timeout must be at least 1 hour'}), 400
            
        setting = db.session.get(SystemSetting, 'session_timeout_hours')
        if not setting:
            setting = SystemSetting(key='session_timeout_hours', value=str(hours))
            db.session.add(setting)
        else:
            setting.value = str(hours)
            
        db.session.commit()
        
        # Update config immediately
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=hours)
        
        return jsonify({'success': True, 'message': 'Session settings saved'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid value'}), 400

@app.route('/api/backups/<filename>/download', methods=['GET'])
@login_required
def download_backup(filename):
    filename = secure_filename(filename)
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    return send_file(path, as_attachment=True)

@app.route('/api/backups/<filename>/restore', methods=['POST'])
@login_required
def restore_backup(filename):
    filename = secure_filename(filename)
    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'error': 'Backup not found'}), 404
        
    try:
        db_path = os.path.join(app.instance_path, 'servers.db')
        # Create a safety backup before restore
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safety_backup = os.path.join(BACKUP_DIR, f'pre_restore_{timestamp}.db')
        if os.path.exists(db_path):
            shutil.copy2(db_path, safety_backup)
            
        # 1. بازگردانی دیتابیس
        shutil.copy2(backup_path, db_path)
        
        # 2. پاک کردن سشن برای امنیت (Log out current user)
        session.clear()
        
        # 3. برگرداندن پاسخ موفقیت + ریدارکت سمت کلاینت
        return jsonify({
            'success': True, 
            'message': 'Database restored successfully. Please login again.',
            'redirect': url_for('login')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/backups/<filename>', methods=['DELETE'])
@login_required
def delete_backup(filename):
    filename = secure_filename(filename)
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    try:
        os.remove(path)
        return jsonify({'success': True, 'message': 'Backup deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user_info():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    return jsonify({
        'success': True,
        'user': user.to_dict()
    })

@app.context_processor
def inject_version():
    return dict(app_version=APP_VERSION)

@app.route('/api/check-update', methods=['GET'])
@login_required
def check_update():
    # Check cache first
    current_time = time.time()
    if UPDATE_CACHE['data'] and (current_time - UPDATE_CACHE['last_check'] < UPDATE_CACHE['ttl']):
        return jsonify(UPDATE_CACHE['data'])

    try:
        resp = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            latest_version = data.get('tag_name', '').lstrip('v')
            
            result = {
                'success': True,
                'current_version': APP_VERSION,
                'latest_version': latest_version,
                'update_available': latest_version != APP_VERSION,
                'release_url': data.get('html_url', '')
            }
            
            # Update cache
            UPDATE_CACHE['last_check'] = current_time
            UPDATE_CACHE['data'] = result
            
            return jsonify(result)
        return jsonify({'success': False, 'error': 'GitHub API error'})
    except Exception as e:
        # If request fails (timeout/network), return cached data if available (even if expired) to avoid error
        if UPDATE_CACHE['data']:
            return jsonify(UPDATE_CACHE['data'])
        return jsonify({'success': False, 'error': str(e)})

def background_data_fetcher():
    """
    این تابع در پس‌زمینه اجرا می‌شود و هر ۳۰ ثانیه اطلاعات را در RAM بروز می‌کند.
    """
    with app.app_context():
        ensure_background_threads_started()
        while True:
            # Avoid overlapping with a manual refresh job.
            if GLOBAL_REFRESH_LOCK.acquire(blocking=False):
                try:
                    fetch_and_update_global_data(force=False)
                finally:
                    try:
                        GLOBAL_REFRESH_LOCK.release()
                    except Exception:
                        pass
            time.sleep(30)


def fetch_and_update_global_data(force: bool = False, server_ids=None):
    """یک بار داده‌ها را از سرورها واکشی و در RAM به‌روزرسانی می‌کند."""
    try:
        GLOBAL_SERVER_DATA['is_updating'] = True

        servers_q = Server.query.filter_by(enabled=True)
        if server_ids:
            try:
                ids = [int(x) for x in (server_ids or [])]
                servers_q = servers_q.filter(Server.id.in_(ids))
            except Exception:
                pass

        servers = servers_q.all()

        now_ts = time.time()
        skipped_ids = set()
        if not force:
            for s in servers:
                try:
                    if _backoff_should_skip(int(s.id), now_ts):
                        skipped_ids.add(int(s.id))
                except Exception:
                    continue

        server_dicts = [{
            'id': s.id, 'name': s.name, 'host': s.host,
            'username': s.username, 'password': s.password,
            'panel_type': s.panel_type, 'sub_port': s.sub_port,
            'sub_path': s.sub_path, 'json_path': s.json_path
        } for s in servers if int(s.id) not in skipped_ids]

        results = []
        if server_dicts:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_id = {executor.submit(fetch_worker, s): s['id'] for s in server_dicts}
                for future in concurrent.futures.as_completed(future_to_id):
                    results.append(future.result())

        results_by_id = {r[0]: r for r in results if isinstance(r, tuple) and len(r) >= 4}

        existing_inbounds = GLOBAL_SERVER_DATA.get('inbounds') or []
        existing_by_server = defaultdict(list)
        for inbound in existing_inbounds:
            try:
                sid = int(inbound.get('server_id', -1))
                if sid > 0:
                    existing_by_server[sid].append(inbound)
            except Exception:
                continue

        existing_statuses = GLOBAL_SERVER_DATA.get('servers_status') or []
        status_map = {}
        for st in existing_statuses:
            try:
                if isinstance(st, dict) and 'server_id' in st:
                    status_map[int(st.get('server_id'))] = st
            except Exception:
                continue

        admin_user = Admin.query.filter(or_(Admin.is_superadmin == True, Admin.role == 'superadmin')).first()
        if not admin_user:
            admin_user = SimpleNamespace(role='superadmin', id=0, is_superadmin=True)

        now_iso = _utc_iso_now()
        new_by_server = dict(existing_by_server)

        for srv in servers:
            sid = int(srv.id)

            if sid in skipped_ids:
                info = _backoff_get(sid)
                st = status_map.get(sid) or {"server_id": sid}
                st['reachable'] = False
                st['reachable_error'] = (info.get('last_error') or 'Backoff')
                st['reachable_checked_at'] = now_iso
                st['backoff_until'] = int(info.get('next_allowed_at', 0) or 0)
                status_map[sid] = st
                continue

            res = results_by_id.get(sid) or (sid, None, "Timeout", 'auto')
            _, inbounds, error, detected_type = res

            if error:
                _backoff_record_failure(sid, error)
                st = status_map.get(sid) or {"server_id": sid}
                # Keep cached stats if present to avoid UI dropping counts.
                if isinstance(st.get('stats'), dict) and st.get('stats'):
                    st['success'] = True
                else:
                    st['success'] = False
                st['error'] = error
                st['reachable'] = False
                st['reachable_error'] = error
                st['reachable_checked_at'] = now_iso
                status_map[sid] = st
                # keep existing inbounds block (if any)
                continue

            _backoff_record_success(sid)

            if persist_detected_panel_type(srv, detected_type):
                app.logger.info(f"Detected panel type for server {srv.id} as {detected_type}")

            processed, stats = process_inbounds(inbounds, srv, admin_user, '*', {})
            new_by_server[sid] = list(processed or [])

            st = status_map.get(sid) or {"server_id": sid}
            st.update({
                "server_id": sid,
                "success": True,
                "stats": stats,
                "panel_type": srv.panel_type,
                "reachable": True,
                "reachable_error": None,
                "reachable_checked_at": now_iso,
                "error": None
            })
            status_map[sid] = st

        # Flatten inbounds in stable order (server order)
        all_inbounds = []
        for srv in servers:
            all_inbounds.extend(new_by_server.get(int(srv.id), []))

        server_statuses = []
        for srv in servers:
            sid = int(srv.id)
            server_statuses.append(status_map.get(sid) or {"server_id": sid, "success": False, "error": "No data"})

        total_stats = _recompute_global_stats_from_server_statuses(server_statuses)

        GLOBAL_SERVER_DATA['inbounds'] = all_inbounds
        GLOBAL_SERVER_DATA['stats'] = total_stats
        GLOBAL_SERVER_DATA['servers_status'] = server_statuses
        GLOBAL_SERVER_DATA['last_update'] = now_iso

    except Exception as e:
        print(f"Background fetch error: {e}")
    finally:
        GLOBAL_SERVER_DATA['is_updating'] = False

def run_scheduler():
    with app.app_context():
        while True:
            try:
                freq_setting = db.session.get(SystemSetting, 'backup_frequency')
                if freq_setting and freq_setting.value != 'disabled':
                    last_backup = db.session.get(SystemSetting, 'last_auto_backup')
                    
                    should_backup = False
                    now = datetime.now()
                    
                    if not last_backup:
                        should_backup = True
                    else:
                        last_time = datetime.fromisoformat(last_backup.value)
                        if freq_setting.value == 'daily' and (now - last_time) > timedelta(days=1):
                            should_backup = True
                        elif freq_setting.value == 'weekly' and (now - last_time) > timedelta(weeks=1):
                            should_backup = True
                        elif freq_setting.value == 'monthly' and (now - last_time) > timedelta(days=30):
                            should_backup = True
                            
                    if should_backup:
                        db_path = os.path.join(app.instance_path, 'servers.db')
                        if os.path.exists(db_path):
                            timestamp = now.strftime('%Y%m%d_%H%M%S')
                            filename = f'auto_{timestamp}.db'
                            dest = os.path.join(BACKUP_DIR, filename)
                            shutil.copy2(db_path, dest)
                            
                            # Update last backup time
                            if not last_backup:
                                last_backup = SystemSetting(key='last_auto_backup', value=now.isoformat())
                                db.session.add(last_backup)
                            else:
                                last_backup.value = now.isoformat()
                            db.session.commit()
                            print(f"Auto backup created: {filename}")
                            
            except Exception as e:
                print(f"Scheduler error: {e}")
            
            time.sleep(3600) # Check every hour

def update_session_lifetime():
    with app.app_context():
        try:
            # Check if table exists first to avoid error on fresh install
            inspector = inspect(db.engine)
            if 'system_settings' in inspector.get_table_names():
                setting = db.session.get(SystemSetting, 'session_timeout_hours')
                if setting:
                    hours = int(setting.value)
                    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=hours)
                    print(f"Session lifetime updated to {hours} hours")
        except Exception as e:
            print(f"Error updating session lifetime: {e}")


def ensure_background_threads_started():
    """Start background threads (scheduler + fetcher) once per process."""
    global BACKGROUND_THREADS_STARTED
    if BACKGROUND_THREADS_STARTED:
        return

    BACKGROUND_THREADS_STARTED = True

    try:
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    except Exception as e:
        print(f"Failed to start scheduler thread: {e}")

    try:
        data_thread = threading.Thread(target=background_data_fetcher, daemon=True)
        data_thread.start()
    except Exception as e:
        print(f"Failed to start data fetcher thread: {e}")

if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
    # Start threads on module import (works under gunicorn as well)
    ensure_background_threads_started()


if __name__ == '__main__':
    # Create tables if not exist
    with app.app_context():
        db.create_all()
    
    update_session_lifetime()

    # Ensure background threads are running
    if not os.environ.get('DISABLE_BACKGROUND_THREADS'):
        ensure_background_threads_started()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
