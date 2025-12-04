import os
import io
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
            'allowed_servers': json.loads(self.allowed_servers) if self.allowed_servers else [],
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

with app.app_context():
    db.create_all()
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
        admin = Admin.query.get(session['admin_id'])
        if not admin or (admin.role != 'superadmin' and not admin.is_superadmin):
            return jsonify({"success": False, "error": "Access Denied: SuperAdmin only"}), 403
        return f(*args, **kwargs)
    return decorated_function

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
        from jdatetime import datetime as jdatetime_class
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
    endpoints = ["/panel/api/inbounds/list", "/xui/inbound/list", "/panel/inbound/list"]
    for ep in endpoints:
        try:
            if 'xui' in ep:
                resp = session_obj.post(f"{host}{ep}", json={"page": 1, "limit": 100}, verify=False, timeout=10)
            else:
                resp = session_obj.get(f"{host}{ep}", verify=False, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    if 'obj' in data: return data['obj'], None
                    if 'data' in data:
                        d = data['data']
                        return d if isinstance(d, list) else d.get('list', []), None
        except: continue
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

                client_data = {
                    "email": email,
                    "id": client.get('id', ''),
                    "subId": sub_id,
                    "enable": client.get('enable', True),
                    "totalGB": client.get('totalGB', 0),
                    "totalGB_formatted": format_bytes(client.get('totalGB', 0)) if client.get('totalGB', 0) > 0 else "Unlimited",
                    "expiryTime": format_remaining_days(client.get('expiryTime', 0))['text'],
                    "expiryType": format_remaining_days(client.get('expiryTime', 0))['type'],
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

            processed.append({
                "id": inbound.get('id'),
                "remark": inbound.get('remark', ''),
                "port": inbound.get('port', ''),
                "protocol": inbound.get('protocol', ''),
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
    user = Admin.query.get(session['admin_id'])
    
    if user.role == 'reseller':
        allowed_ids = json.loads(user.allowed_servers) if user.allowed_servers and user.allowed_servers != '*' else []
        if user.allowed_servers == '*':
            servers = Server.query.filter_by(enabled=True).all()
        else:
            servers = Server.query.filter(Server.id.in_(allowed_ids), Server.enabled == True).all() if allowed_ids else []
    else:
        servers = Server.query.filter_by(enabled=True).all()
        
    return render_template('dashboard.html', 
                         servers=servers, 
                         server_count=len(servers),
                         admin_username=user.username,
                         is_superadmin=(user.role == 'superadmin' or user.is_superadmin),
                         role=user.role,
                         credit=user.credit)

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
    user = Admin.query.get(session['admin_id'])
    
    if user.role == 'reseller':
        allowed_ids = json.loads(user.allowed_servers) if user.allowed_servers and user.allowed_servers != '*' else []
        if user.allowed_servers == '*':
            servers = Server.query.filter_by(enabled=True).all()
        else:
            servers = Server.query.filter(Server.id.in_(allowed_ids), Server.enabled == True).all() if allowed_ids else []
    else:
        servers = Server.query.filter_by(enabled=True).all()
    
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

@app.route('/api/client/<int:server_id>/<int:inbound_id>/toggle', methods=['POST'])
@login_required
def toggle_client(server_id, inbound_id):
    user = Admin.query.get(session['admin_id'])
    server = Server.query.get_or_404(server_id)
    email = request.json.get('email')
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
        resp = session_obj.post(f"{server.host}/xui/client/update", json={"id": inbound_id, "settings": json.dumps({"clients": [{"email": email}]})}, verify=False, timeout=10)
        if resp.status_code == 200: return jsonify({"success": True})
        return jsonify({"success": False, "error": "Failed to toggle"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/client/<int:server_id>/<int:inbound_id>/reset', methods=['POST'])
@login_required
def reset_client_traffic(server_id, inbound_id):
    user = Admin.query.get(session['admin_id'])
    server = Server.query.get_or_404(server_id)
    email = request.json.get('email')
    
    if user.role == 'reseller':
        ownership = ClientOwnership.query.filter_by(reseller_id=user.id, server_id=server_id, client_email=email).first()
        if not ownership:
            return jsonify({"success": False, "error": "Access denied"}), 403
    
    session_obj, error = get_xui_session(server)
    if error: return jsonify({"success": False, "error": error}), 400
    
    try:
        resp = session_obj.post(f"{server.host}/xui/client/reset", json={"email": email}, verify=False, timeout=10)
        if resp.status_code == 200: return jsonify({"success": True})
        return jsonify({"success": False, "error": "Failed to reset"}), 400
    except Exception as e:
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
        allowed_servers=json.dumps(data.get('allowed_servers', [])),
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
    if 'allowed_servers' in data: admin.allowed_servers = json.dumps(data['allowed_servers'])
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
    user = Admin.query.get(session['admin_id'])
    if user.role == 'reseller':
        allowed_ids = json.loads(user.allowed_servers) if user.allowed_servers and user.allowed_servers != '*' else []
        if user.allowed_servers == '*':
            servers = Server.query.filter_by(enabled=True).all()
        else:
            servers = Server.query.filter(Server.id.in_(allowed_ids), Server.enabled == True).all() if allowed_ids else []
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

@app.route('/sub-manager')
@superadmin_required
def sub_manager_page():
    user = Admin.query.get(session['admin_id'])
    return render_template('sub_manager.html', admin_username=user.username, role=user.role, is_superadmin=True)

@app.route('/api/sub-apps', methods=['GET'])
def get_sub_apps():
    apps = SubAppConfig.query.all()
    return jsonify([a.to_dict() for a in apps])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
