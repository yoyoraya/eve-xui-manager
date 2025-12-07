import os
import io
import re
import json
import base64
import requests
import qrcode
import uuid
import secrets
import string
import shutil
import glob
import threading
import time
import concurrent.futures
from types import SimpleNamespace
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, quote
from jdatetime import datetime as jdatetime_class
from sqlalchemy import or_, func, text, inspect

APP_VERSION = "1.2.1"
GITHUB_REPO = "yoyoraya/eve-xui-manager"

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Use SQLite by default, but allow override via DATABASE_URL
db_url = os.environ.get("DATABASE_URL")
if not db_url or db_url.startswith("postgresql://"):
    # Fallback to SQLite if DATABASE_URL is missing or points to the old postgres config
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
            'is_enabled': self.is_enabled,
            'title_fa': self.title_fa,
            'description_fa': self.description_fa,
            'title_en': self.title_en,
            'description_en': self.description_en,
            'download_link': self.download_link,
            'store_link': self.store_link,
            'tutorial_link': self.tutorial_link
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

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(20))
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        admin_info = None
        if hasattr(self, 'admin') and self.admin:
            admin_info = {
                'id': self.admin.id,
                'username': self.admin.username,
                'role': self.admin.role
            }
        return {
            'id': self.id,
            'admin_id': self.admin_id,
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
    host_clean = host.rstrip('/')
    endpoint_clean = endpoint if endpoint.startswith('/') else f"/{endpoint}"
    return f"{host_clean}{endpoint_clean}"

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
    
    initial_username = os.environ.get("INITIAL_ADMIN_USERNAME", "admin")
    if not Admin.query.filter_by(username=initial_username).first():
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
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
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

def log_transaction(user_id, amount, type, desc):
    trans = Transaction(admin_id=user_id, amount=amount, type=type, description=desc)
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
        jalali_date = jdatetime_class.fromgregorian(datetime=dt)
        return jalali_date.strftime('%Y/%m/%d %H:%M')
    except Exception:
        return dt.isoformat() if dt else None

EMAIL_IN_DESCRIPTION = re.compile(r'([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)$')

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
            if 'H' not in pattern:
                day = gregorian.date()
                time_part = datetime.max.time() if end_of_day else datetime.min.time()
                return datetime.combine(day, time_part)
            return gregorian
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
    try:
        parsed = json.loads(normalized)
        if isinstance(parsed, str) and parsed.strip() == '*':
            return '*'
        return parsed if isinstance(parsed, list) else parsed
    except Exception:
        return []

def serialize_allowed_servers(value):
    if value == '*' or (isinstance(value, str) and value.strip() == '*'):
        return '*'
    if isinstance(value, list):
        cleaned = []
        for item in value:
            try:
                cleaned.append(int(item))
            except (TypeError, ValueError):
                continue
        return json.dumps(cleaned)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return serialize_allowed_servers(parsed)
            if isinstance(parsed, str) and parsed.strip() == '*':
                return '*'
        except Exception:
            pass
    return json.dumps([])

def resolve_allowed_servers(raw_value):
    parsed = parse_allowed_servers(raw_value)
    if parsed == '*':
        return '*'
    if isinstance(parsed, list):
        cleaned = []
        for item in parsed:
            try:
                cleaned.append(int(item))
            except (TypeError, ValueError):
                continue
        return cleaned
    return []

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
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def format_remaining_days(timestamp):
    if timestamp == 0 or timestamp is None:
        return {"text": "Unlimited", "days": -1, "type": "unlimited"}
    if timestamp < 0:
        days = abs(timestamp) // 86400000
        return {"text": f"Not started ({days} days)", "days": days, "type": "start_after_use"}
    try:
        expiry_date = datetime.fromtimestamp(timestamp/1000)
        now = datetime.now()
        jalali_date = jdatetime_class.fromgregorian(datetime=expiry_date)
        
        if expiry_date < now:
            days_ago = (now - expiry_date).days
            return {"text": f"Expired ({days_ago}d ago)", "days": -days_ago, "type": "expired"}
        
        days = (expiry_date - now).days
        if days == 0: return {"text": f"Today [{jalali_date.strftime('%Y-%m-%d')}]", "days": 0, "type": "today"}
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
        allowed_ids = resolve_allowed_servers(user.allowed_servers)
        if allowed_ids == '*':
            return query.all()
        if not allowed_ids:
            return []
        return query.filter(Server.id.in_(allowed_ids)).all()
    return query.all()

def get_xui_session(server):
    session_obj = requests.Session()
    try:
        login_resp = session_obj.post(f"{server.host}/login", data={"username": server.username, "password": server.password}, verify=False, timeout=10)
        if login_resp.status_code == 200 and login_resp.json().get('success'):
            return session_obj, None
        return None, f"Login failed: {login_resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)}"

def fetch_inbounds(session_obj, host, panel_type='auto'):
    panel_api = get_panel_api(panel_type)
    endpoints = []
    if panel_api and panel_api.inbounds_list:
        endpoints.append(panel_api.inbounds_list)
    endpoints.extend(["/panel/api/inbounds/list", "/xui/API/inbounds/", "/xui/inbound/list"])
    
    for ep in endpoints:
        if not ep:
            continue
        try:
            url = ep if ep.startswith('http') else f"{host}{ep}"
            if '/xui/' in ep.lower() and 'api' in ep.lower():
                resp = session_obj.get(url, verify=False, timeout=10)
            elif '/xui/' in ep.lower():
                resp = session_obj.post(url, json={"page": 1, "limit": 100}, verify=False, timeout=10)
            else:
                resp = session_obj.get(url, verify=False, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    if 'obj' in data: return data['obj'], None
                    if 'data' in data:
                        d = data['data']
                        return d if isinstance(d, list) else d.get('list', []), None
        except Exception as e:
            app.logger.debug(f"Failed inbounds endpoint {ep}: {str(e)}")
            continue
    return None, "Failed to fetch inbounds"

def generate_client_link(client, inbound, server_host):
    try:
        protocol = inbound.get('protocol', '').lower()
        uuid = client.get('id', '')
        remark = client.get('email', 'client')
        port = inbound.get('port')
        parsed = urlparse(server_host)
        host = parsed.hostname
        if protocol == 'vless':
            return f"vless://{uuid}@{host}:{port}?type=tcp&security=none#{remark}"
        return f"{protocol}://..."
    except: return None

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

def process_inbounds(inbounds, server, user):
    processed = []
    stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "active_clients": 0, "inactive_clients": 0, "upload_raw": 0, "download_raw": 0}
    
    owned_emails = []
    if user.role == 'reseller':
        ownerships = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server.id).all()
        owned_emails = [o.client_email for o in ownerships]

    for inbound in inbounds:
        try:
            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            client_stats = inbound.get('clientStats', [])
            
            processed_clients = []
            for client in clients:
                email = client.get('email', '')
                
                if user.role == 'reseller' and email not in owned_emails:
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
                    app_base = request.url_root.rstrip('/')
                    
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
                total_formatted = format_bytes(total_bytes) if total_bytes > 0 else "Unlimited"
                remaining_formatted = format_bytes(remaining_bytes) if remaining_bytes is not None else "Unlimited"

                expiry_info = format_remaining_days(client.get('expiryTime', 0))

                client_data = {
                    "email": email,
                    "id": client.get('id', ''),
                    "subId": sub_id,
                    "enable": client.get('enable', True),
                    "totalGB": total_bytes,
                    "totalGB_formatted": total_formatted,
                    "remaining_bytes": remaining_bytes if remaining_bytes is not None else -1,
                    "remaining_formatted": remaining_formatted,
                    "expiryTime": expiry_info['text'],
                    "expiryType": expiry_info['type'],
                    "up": format_bytes(client_up),
                    "down": format_bytes(client_down),
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
            
            if user.role == 'reseller' and not processed_clients:
                continue

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
                "total_down": format_bytes(inbound.get('down', 0))
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
        
    return render_template('dashboard.html', 
                         servers=servers, 
                         server_count=len(servers),
                         admin_username=user.username,
                         is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                         role=user.role,
                         credit=user.credit,
                         base_cost_day=user_cost_day,
                         base_cost_gb=user_cost_gb)

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
            return server_dict['id'], None, error
        
        inbounds, fetch_error = fetch_inbounds(session_obj, server_obj.host, server_obj.panel_type)
        return server_dict['id'], inbounds, fetch_error

@app.route('/api/refresh')
@login_required
def api_refresh():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    
    all_inbounds = []
    total_stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "active_clients": 0, "inactive_clients": 0, "upload_raw": 0, "download_raw": 0}
    server_results = []
    
    # Prepare data for threads
    server_dicts = [{
        'id': s.id, 
        'name': s.name, 
        'host': s.host, 
        'username': s.username, 
        'password': s.password, 
        'panel_type': s.panel_type,
        'sub_port': s.sub_port,
        'sub_path': s.sub_path,
        'json_path': s.json_path
    } for s in servers]
    
    # Parallel fetch
    fetched_data = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_id = {executor.submit(fetch_worker, s): s['id'] for s in server_dicts}
        for future in concurrent.futures.as_completed(future_to_id):
            srv_id, inbounds, error = future.result()
            fetched_data[srv_id] = (inbounds, error)
            
    for server in servers:
        inbounds, error = fetched_data.get(server.id, (None, "Unknown error"))
        
        if error:
            server_results.append({"server_id": server.id, "server_name": server.name, "success": False, "error": error})
            continue
        
        processed_inbounds, stats = process_inbounds(inbounds, server, user)
        all_inbounds.extend(processed_inbounds)
        
        total_stats["total_inbounds"] += stats["total_inbounds"]
        total_stats["active_inbounds"] += stats["active_inbounds"]
        total_stats["total_clients"] += stats["total_clients"]
        total_stats["active_clients"] += stats["active_clients"]
        total_stats["inactive_clients"] += stats["inactive_clients"]
        total_stats["upload_raw"] += stats["upload_raw"]
        total_stats["download_raw"] += stats["download_raw"]
        
        server_results.append({"server_id": server.id, "server_name": server.name, "success": True, "stats": stats, "panel_type": server.panel_type})
    
    total_stats["total_upload"] = format_bytes(total_stats["upload_raw"])
    total_stats["total_download"] = format_bytes(total_stats["download_raw"])
    total_stats["total_traffic"] = format_bytes(total_stats["upload_raw"] + total_stats["download_raw"])
    
    return jsonify({"success": True, "inbounds": all_inbounds, "stats": total_stats, "servers": server_results, "server_count": len(servers)})


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
    query = (request.args.get('email') or '').strip()
    if not query:
        return jsonify({"success": False, "error": "Query parameter 'email' is required"}), 400

    try:
        limit = int(request.args.get('limit', 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    search_term = query.lower()
    servers = get_accessible_servers(user)
    if not servers:
        return jsonify({"success": True, "results": [], "errors": ["No accessible servers"]})

    matches = []
    errors = []
    for server in servers:
        session_obj, error = get_xui_session(server)
        if error:
            errors.append({"server_id": server.id, "server_name": server.name, "error": error})
            continue

        inbounds, fetch_error = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_error:
            errors.append({"server_id": server.id, "server_name": server.name, "error": fetch_error})
            continue

        processed_inbounds, _ = process_inbounds(inbounds or [], server, user)
        for inbound in processed_inbounds:
            inbound_clients = inbound.get('clients', [])
            for client in inbound_clients:
                client_email = client.get('email', '')
                if not client_email:
                    continue
                if search_term not in client_email.lower():
                    continue
                matches.append({
                    "server_id": server.id,
                    "server_name": server.name,
                    "panel_type": server.panel_type,
                    "inbound_id": inbound.get('id'),
                    "inbound": {
                        "id": inbound.get('id'),
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
        if len(matches) >= limit:
            break

    return jsonify({"success": True, "results": matches, "errors": errors})

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
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
        if price > user.credit:
            return jsonify({"success": False, "error": f"Insufficient credit. Required: {price}, Available: {user.credit}"}), 402
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
        inbounds, fetch_err = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": fetch_err}), 400
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
                    log_transaction(user.id, -price, 'renew', description or f"Renew client {email}")
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
                
                if user.role == 'reseller' and charge_amount > 0:
                    user.credit -= charge_amount
                
                if charge_amount > 0:
                    log_transaction(user.id, -charge_amount, 'reset_traffic', f"Reset traffic {volume_gb}GB - {email}")
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
        inbounds, fetch_err = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_err:
            return jsonify({"success": False, "error": "Failed to fetch inbounds"}), 400
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

                if user.role == 'reseller' and price > 0:
                    user.credit -= price
                
                if price > 0:
                    log_transaction(user.id, -price, 'renew', description)
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
    
    data = request.json or {}
    email = data.get('email', '').strip()
    mode = data.get('mode', 'custom')
    start_after_first_use = bool(data.get('start_after_first_use', False))
    
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

    if user.role == 'reseller':
        allowed = resolve_allowed_servers(user.allowed_servers)
        if allowed != '*' and server_id not in allowed:
            return jsonify({"success": False, "error": "Access to this server is denied"}), 403
        
        if user.credit < price:
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
        
        if server.panel_type == 'alireza':
             get_url = f"{server.host}/xui/inbound/get/{inbound_id}"
        else:
             get_url = f"{server.host}/panel/api/inbounds/get/{inbound_id}"
             
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
            up_url = f"{server.host}/xui/inbound/update/{inbound_id}"
        else:
            up_url = f"{server.host}/panel/api/inbounds/update/{inbound_id}"
            
        up_resp = session_obj.post(up_url, json=update_data, verify=False, timeout=10)
        
        if up_resp.status_code == 200 and up_resp.json().get('success'):
            
            if user.role == 'reseller' and price > 0:
                user.credit -= price
            
            if price > 0:
                log_transaction(user.id, -price, 'purchase', description)
            
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

    transaction = Transaction(
        admin_id=admin_id,
        amount=amount,
        type=transaction_type,
        description=description
    )
    db.session.add(transaction)
    db.session.commit()
    return jsonify({"success": True, "new_credit": admin.credit})

@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    user = db.session.get(Admin, session['admin_id'])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 401

    query = Transaction.query.join(Admin)

    if user.role == 'reseller':
        query = query.filter(Transaction.admin_id == user.id)
    else:
        target_user_id = request.args.get('user_id', type=int)
        if target_user_id:
            query = query.filter(Transaction.admin_id == target_user_id)

    search_term = (request.args.get('search') or '').strip()
    if search_term:
        pattern = f"%{search_term}%"
        query = query.filter(or_(
            Transaction.description.ilike(pattern),
            Transaction.type.ilike(pattern),
            Admin.username.ilike(pattern)
        ))

    start_dt = parse_jalali_date(request.args.get('start_date'), end_of_day=False)
    if start_dt:
        query = query.filter(Transaction.created_at >= start_dt)

    end_dt = parse_jalali_date(request.args.get('end_date'), end_of_day=True)
    if end_dt:
        query = query.filter(Transaction.created_at <= end_dt)

    limit = request.args.get('limit', type=int)
    if limit is None:
        limit = 300
    limit = max(1, min(limit, 1000))

    query = query.order_by(Transaction.created_at.desc())
    transactions = query.limit(limit).all()

    server_filter = request.args.get('server_id', type=int)
    if server_filter:
        accessible_ids = {s.id for s in get_accessible_servers(user, include_disabled=True)}
        if user.role == 'reseller' and (not accessible_ids or server_filter not in accessible_ids):
            return jsonify({"success": False, "error": "Access denied to requested server"}), 403

    transaction_emails = {}
    email_pairs = set()
    for tx in transactions:
        email = extract_email_from_description(tx.description)
        if not email:
            continue
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
        email = transaction_emails.get(tx.id)
        tx_data['client_email'] = email
        server_meta = None
        server_id = None
        if email:
            ownership = ownership_map.get((tx.admin_id, email))
            if ownership:
                server_id = ownership.server_id
                server_meta = {
                    'id': ownership.server_id,
                    'name': ownership.server.name if ownership.server else None
                }
        if server_filter and server_id != server_filter:
            continue
        tx_data['server'] = server_meta
        payload.append(tx_data)

    return jsonify(payload)

@app.route('/s/<int:server_id>/<sub_id>')
def client_subscription(server_id, sub_id):
    server = db.session.get(Server, server_id)
    if not server:
        return "Subscription not found", 404

    session_obj, login_error = get_xui_session(server)
    if login_error or not session_obj:
        app.logger.warning(f"Dash sub auth failed for server {server_id}: {login_error}")
        return "Unable to load subscription", 502

    inbounds, fetch_error = fetch_inbounds(session_obj, server.host, server.panel_type)
    if fetch_error or not inbounds:
        app.logger.warning(f"Dash sub fetch failed for server {server_id}: {fetch_error}")
        return "Unable to load subscription", 502

    normalized_sub_id = str(sub_id).strip()
    target_client = None
    target_inbound = None

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

    expiry_info = format_remaining_days(target_client.get('expiryTime', 0))

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

    configs = []
    direct_link = generate_client_link(target_client, target_inbound, server.host)
    if direct_link:
        configs.append(direct_link)

    subscription_entries = [entry for entry in configs if entry]
    if not subscription_entries:
        subscription_entries.append(sub_url)
    subscription_blob = '\n'.join(subscription_entries)
    encoded_blob = base64.b64encode((subscription_blob or '').encode('utf-8')).decode('utf-8') if subscription_blob else ''

    user_agent = (request.headers.get('User-Agent') or '').lower()
    agent_tokens = ['v2ray', 'xray', 'streisand', 'shadowrocket', 'nekoray', 'nekobox', 'clash', 'sing-box']
    wants_b64 = request.args.get('format', '').lower() == 'b64'
    if encoded_blob and (wants_b64 or any(token in user_agent for token in agent_tokens)):
        return encoded_blob, 200, {'Content-Type': 'text/plain; charset=utf-8'}

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
    }

    apps = SubAppConfig.query.filter_by(is_enabled=True).all()
    apps_payload = [app.to_dict() for app in apps]

    return render_template('subscription.html', client=client_payload, apps=apps_payload)

@app.route('/sub-manager')
@superadmin_required
def sub_manager_page():
    user = db.session.get(Admin, session['admin_id'])
    return render_template('sub_manager.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False),
                         role=session.get('role', 'admin'))

@app.route('/api/sub-apps', methods=['GET'])
def get_sub_apps():
    apps = SubAppConfig.query.all()
    return jsonify([a.to_dict() for a in apps])

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
            
        shutil.copy2(backup_path, db_path)
        return jsonify({'success': True, 'message': 'Database restored successfully'})
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
    try:
        resp = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            latest_version = data.get('tag_name', '').lstrip('v')
            return jsonify({
                'success': True,
                'current_version': APP_VERSION,
                'latest_version': latest_version,
                'update_available': latest_version != APP_VERSION,
                'release_url': data.get('html_url', '')
            })
        return jsonify({'success': False, 'error': 'GitHub API error'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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

if __name__ == '__main__':
    # Create tables if not exist
    with app.app_context():
        db.create_all()
        
    # Start scheduler in background
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
