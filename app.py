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
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, quote
from jdatetime import datetime as jdatetime_class
from sqlalchemy import or_, func

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///servers.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'pool_recycle': 1800,
    'pool_pre_ping': True
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
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
    enabled = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'days': self.days,
            'volume': self.volume,
            'price': self.price,
            'enabled': self.enabled
        }

class SystemConfig(db.Model):
    __tablename__ = 'system_configs'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(200))

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
    
    if not Admin.query.filter_by(username='admin').first():
        default_admin = Admin(
            username='admin',
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
        
    return render_template('dashboard.html', 
                         servers=servers, 
                         server_count=len(servers),
                         admin_username=user.username,
                         is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                         role=user.role,
                         credit=user.credit,
                         base_cost_day=base_cost_day,
                         base_cost_gb=base_cost_gb)

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

@app.route('/api/refresh')
@login_required
def api_refresh():
    user = db.session.get(Admin, session['admin_id'])
    servers = get_accessible_servers(user)
    
    all_inbounds = []
    total_stats = {"total_inbounds": 0, "active_inbounds": 0, "total_clients": 0, "active_clients": 0, "inactive_clients": 0, "upload_raw": 0, "download_raw": 0}
    server_results = []
    
    for server in servers:
        session_obj, error = get_xui_session(server)
        if error:
            server_results.append({"server_id": server.id, "server_name": server.name, "success": False, "error": error})
            continue
        
        inbounds, fetch_error = fetch_inbounds(session_obj, server.host, server.panel_type)
        if fetch_error:
            server_results.append({"server_id": server.id, "server_name": server.name, "success": False, "error": fetch_error})
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


@app.route('/api/clients/search')
@login_required
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
    
    cost_per_gb = get_config('cost_per_gb', 0)
    charge_amount = volume_gb * cost_per_gb if volume_gb > 0 else 0

    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
        if cost_per_gb > 0 and volume_gb <= 0:
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
            price = int(package.price or 0)
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
            cost_per_day = get_config('cost_per_day', 0)
            cost_per_gb = get_config('cost_per_gb', 0)
            price = (days_to_add * cost_per_day) + (volume_gb_to_add * cost_per_gb)
            description = f"Renew Custom: {days_to_add} Days, {volume_gb_to_add} GB - {email}"
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid data"}), 400
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
    
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
        enabled=data.get('enabled', True)
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
    return jsonify({"success": True})

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
        
        price = package.price
        days = package.days
        volume_gb = package.volume
        description = f"Purchase Package: {package.name} - {email}"
        
    else:
        days = int(data.get('days', 30))
        volume_gb = int(data.get('volume', 0))
        
        cost_per_day = get_config('cost_per_day', 0)
        cost_per_gb = get_config('cost_per_gb', 0)
        price = (days * cost_per_day) + (volume_gb * cost_per_gb)
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
            
            return jsonify({"success": True})
        else:
            msg = up_resp.json().get('msg', 'Unknown error') if up_resp.content else 'Panel update failed'
            return jsonify({"success": False, "error": f"Panel Error: {msg}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/packages', methods=['GET'])
@login_required
def get_packages():
    packages = Package.query.filter_by(enabled=True).all()
    return jsonify([p.to_dict() for p in packages])

@app.route('/admin/packages', methods=['POST'])
@superadmin_required
def create_package():
    data = request.json
    package = Package(
        name=data.get('name'),
        days=int(data.get('days')),
        volume=int(data.get('volume')),
        price=int(data.get('price')),
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
