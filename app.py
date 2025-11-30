import os
import io
import json
import base64
import requests
import qrcode
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
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

db = SQLAlchemy(app)

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)
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
            'is_superadmin': self.is_superadmin,
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'username': self.username,
            'enabled': self.enabled,
            'panel_type': self.panel_type,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

with app.app_context():
    db.create_all()
    if not Admin.query.filter_by(username='admin').first():
        default_admin = Admin(username='admin', is_superadmin=True, enabled=True)
        default_admin.set_password('admin')
        db.session.add(default_admin)
        db.session.commit()

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
        if not admin or not admin.is_superadmin:
            return jsonify({"success": False, "error": "Superadmin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def format_bytes(size):
    if size is None or size == 0:
        return "0 B"
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
    
    # Handle negative timestamps (Start After First Use feature)
    # Formula: -1 * (days * 86400000)
    # X-UI panel converts this to positive timestamp after first connection
    if timestamp < 0:
        ms_per_day = 86400000
        days = abs(timestamp) // ms_per_day
        return {"text": f"Not started yet (Validity: {days} days)", "days": days, "type": "start_after_use"}
    
    try:
        expiry_date = datetime.fromtimestamp(timestamp/1000)
        now = datetime.now()
        
        # Format as Jalali (Persian) calendar
        from jdatetime import datetime as jdatetime_class
        jalali_date = jdatetime_class.fromgregorian(datetime=expiry_date)
        jalali_today = jdatetime_class.fromgregorian(datetime=now)
        
        if expiry_date < now:
            days_ago = (now - expiry_date).days
            return {"text": f"Expired ({days_ago}d ago) [{jalali_date.strftime('%Y-%m-%d')}]", "days": -days_ago, "type": "expired"}
        
        remaining = expiry_date - now
        days = remaining.days
        
        if days == 0:
            hours = remaining.seconds // 3600
            return {"text": f"{hours}h remaining [{jalali_date.strftime('%Y-%m-%d')}]", "days": 0, "type": "today"}
        elif days == 1:
            return {"text": f"1 day remaining [{jalali_date.strftime('%Y-%m-%d')}]", "days": 1, "type": "soon"}
        elif days < 7:
            return {"text": f"{days} days remaining [{jalali_date.strftime('%Y-%m-%d')}]", "days": days, "type": "soon"}
        else:
            return {"text": f"{days} days remaining [{jalali_date.strftime('%Y-%m-%d')}]", "days": days, "type": "normal"}
    except:
        return {"text": "Invalid Date", "days": 0, "type": "error"}

def get_xui_session(server):
    session_obj = requests.Session()
    login_url = f"{server.host}/login"
    login_data = {
        "username": server.username,
        "password": server.password
    }
    
    try:
        login_resp = session_obj.post(login_url, data=login_data, verify=False, timeout=10)
        
        if login_resp.status_code == 200:
            resp_json = login_resp.json()
            if resp_json.get('success'):
                return session_obj, None
            else:
                return None, f"Login failed: {resp_json.get('msg', 'Unknown error')}"
        else:
            return None, f"Login failed with status code: {login_resp.status_code}"
    except requests.exceptions.ConnectionError:
        return None, "Cannot connect to server"
    except requests.exceptions.Timeout:
        return None, "Connection timed out"
    except Exception as e:
        return None, f"Error: {str(e)}"

def detect_panel_type(session_obj, host):
    try:
        resp = session_obj.get(f"{host}/panel/api/inbounds/list", verify=False, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success') is not None and 'obj' in data:
                return 'sanaei'
    except:
        pass
    
    try:
        resp = session_obj.post(f"{host}/xui/inbound/list", json={"page": 1, "limit": 1}, verify=False, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success') is not None:
                return 'alireza'
    except:
        pass
    
    try:
        resp = session_obj.get(f"{host}/panel/inbound/list", verify=False, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success') is not None:
                return 'sanaei'
    except:
        pass
    
    return 'unknown'

def parse_alireza_inbounds(data):
    if data.get('obj'):
        obj = data.get('obj')
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            return obj.get('inbounds', obj.get('list', []))
    if data.get('data'):
        inner = data.get('data')
        if isinstance(inner, list):
            return inner
        if isinstance(inner, dict):
            return inner.get('list', inner.get('inbounds', []))
    return []

def fetch_inbounds(session_obj, host, panel_type='auto'):
    if panel_type == 'alireza':
        try:
            list_resp = session_obj.post(f"{host}/xui/inbound/list", json={"page": 1, "limit": 100}, verify=False, timeout=10)
            if list_resp.status_code == 200:
                data = list_resp.json()
                if data.get('success'):
                    inbounds = parse_alireza_inbounds(data)
                    return inbounds, None
        except:
            pass
        return None, "Failed to fetch inbounds from Alireza panel"
    
    sanaei_endpoints = [
        "/panel/api/inbounds/list",
        "/panel/inbound/list"
    ]
    
    for endpoint in sanaei_endpoints:
        try:
            list_url = f"{host}{endpoint}"
            list_resp = session_obj.get(list_url, verify=False, timeout=10)
            
            if list_resp.status_code == 200:
                data = list_resp.json()
                if data.get('success'):
                    return data.get('obj', []), None
        except:
            continue
    
    if panel_type == 'auto':
        try:
            list_resp = session_obj.post(f"{host}/xui/inbound/list", json={"page": 1, "limit": 100}, verify=False, timeout=10)
            if list_resp.status_code == 200:
                data = list_resp.json()
                if data.get('success'):
                    inbounds = parse_alireza_inbounds(data)
                    return inbounds, None
        except:
            pass
    
    return None, "Failed to fetch inbounds"

def generate_vmess_link(client, inbound, server_host):
    try:
        parsed = urlparse(server_host)
        server_ip = parsed.hostname
        
        stream_settings = json.loads(inbound.get('streamSettings', '{}'))
        
        vmess_obj = {
            "v": "2",
            "ps": client.get('email', 'client'),
            "add": server_ip,
            "port": str(inbound.get('port', '')),
            "id": client.get('id', ''),
            "aid": str(client.get('alterId', 0)),
            "scy": "auto",
            "net": stream_settings.get('network', 'tcp'),
            "type": "none",
            "host": "",
            "path": stream_settings.get('wsSettings', {}).get('path', '') if stream_settings.get('network') == 'ws' else "",
            "tls": stream_settings.get('security', 'none'),
            "sni": stream_settings.get('tlsSettings', {}).get('serverName', ''),
            "alpn": ""
        }
        
        vmess_json = json.dumps(vmess_obj, separators=(',', ':'))
        vmess_b64 = base64.b64encode(vmess_json.encode()).decode()
        return f"vmess://{vmess_b64}"
    except:
        return None

def generate_vless_link(client, inbound, server_host):
    try:
        parsed = urlparse(server_host)
        server_ip = parsed.hostname
        
        stream_settings = json.loads(inbound.get('streamSettings', '{}'))
        network = stream_settings.get('network', 'tcp')
        security = stream_settings.get('security', 'none')
        
        uuid = client.get('id', '')
        port = inbound.get('port', '')
        
        params = [f"type={network}"]
        
        if security == 'tls':
            params.append("security=tls")
            tls_settings = stream_settings.get('tlsSettings', {})
            if tls_settings.get('serverName'):
                params.append(f"sni={tls_settings.get('serverName')}")
        elif security == 'reality':
            params.append("security=reality")
            reality_settings = stream_settings.get('realitySettings', {})
            if reality_settings.get('publicKey'):
                params.append(f"pbk={reality_settings.get('publicKey')}")
            if reality_settings.get('shortIds'):
                params.append(f"sid={reality_settings.get('shortIds', [''])[0]}")
            if reality_settings.get('serverNames'):
                params.append(f"sni={reality_settings.get('serverNames', [''])[0]}")
            params.append(f"fp={reality_settings.get('fingerprint', 'chrome')}")
        
        if network == 'ws':
            ws_settings = stream_settings.get('wsSettings', {})
            if ws_settings.get('path'):
                params.append(f"path={ws_settings.get('path')}")
        elif network == 'grpc':
            grpc_settings = stream_settings.get('grpcSettings', {})
            if grpc_settings.get('serviceName'):
                params.append(f"serviceName={grpc_settings.get('serviceName')}")
        
        flow = client.get('flow', '')
        if flow:
            params.append(f"flow={flow}")
        
        params_str = "&".join(params)
        remark = client.get('email', 'client')
        
        return f"vless://{uuid}@{server_ip}:{port}?{params_str}#{remark}"
    except:
        return None

def generate_trojan_link(client, inbound, server_host):
    try:
        parsed = urlparse(server_host)
        server_ip = parsed.hostname
        
        stream_settings = json.loads(inbound.get('streamSettings', '{}'))
        
        password = client.get('password', '')
        port = inbound.get('port', '')
        remark = client.get('email', 'client')
        
        params = []
        security = stream_settings.get('security', 'tls')
        params.append(f"security={security}")
        
        if security == 'tls':
            tls_settings = stream_settings.get('tlsSettings', {})
            if tls_settings.get('serverName'):
                params.append(f"sni={tls_settings.get('serverName')}")
        
        network = stream_settings.get('network', 'tcp')
        params.append(f"type={network}")
        
        params_str = "&".join(params)
        
        return f"trojan://{password}@{server_ip}:{port}?{params_str}#{remark}"
    except:
        return None

def generate_client_link(client, inbound, server_host):
    protocol = inbound.get('protocol', '').lower()
    
    if protocol == 'vmess':
        return generate_vmess_link(client, inbound, server_host)
    elif protocol == 'vless':
        return generate_vless_link(client, inbound, server_host)
    elif protocol == 'trojan':
        return generate_trojan_link(client, inbound, server_host)
    
    return None

def process_inbounds(inbounds, server):
    processed = []
    total_upload = 0
    total_download = 0
    total_clients = 0
    active_clients = 0
    inactive_clients = 0
    active_inbounds = 0
    
    for inbound in inbounds:
        try:
            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            
            client_stats = inbound.get('clientStats', [])
            
            processed_clients = []
            for client in clients:
                link = generate_client_link(client, inbound, server.host)
                
                expiry_timestamp = client.get('expiryTime', 0)
                total_gb = client.get('totalGB', 0)
                
                client_up = 0
                client_down = 0
                client_total_used = 0
                
                for stat in client_stats:
                    if stat.get('email') == client.get('email'):
                        client_up = stat.get('up', 0)
                        client_down = stat.get('down', 0)
                        client_total_used = client_up + client_down
                        break
                
                remaining_bytes = 0
                if total_gb > 0:
                    total_bytes = total_gb
                    remaining_bytes = max(0, total_bytes - client_total_used)
                
                # "Start After First Use" Feature Detection
                # When a client has negative expiryTime, it means the expiry date
                # should be set AFTER the first connection. This is detected by checking:
                # - expiryTime < 0 (negative timestamp)
                # - expiryTimeStr == 'StartAfterFirstUse' (string indicator)
                # - expiryOption == 'after_first_use' (option field indicator)
                # The panel will update the expiry time after the client's first connection.
                is_start_after_first_use = False
                if expiry_timestamp < 0:
                    is_start_after_first_use = True
                elif expiry_timestamp == 0 and client.get('enable', True):
                    if str(client.get('expiryTimeStr', '')).lower() == 'startafterfirstuse':
                        is_start_after_first_use = True
                    elif client.get('expiryOption') == 'after_first_use':
                        is_start_after_first_use = True
                
                expiry_info = format_remaining_days(expiry_timestamp)
                
                client_data = {
                    "email": client.get('email', 'N/A'),
                    "id": client.get('id', client.get('password', 'N/A')),
                    "uuid": client.get('id', ''),
                    "subId": client.get('subId', ''),
                    "enable": client.get('enable', True),
                    "expiryTime": expiry_info['text'],
                    "expiryType": expiry_info['type'],
                    "expiryDays": expiry_info['days'],
                    "expiryTimestamp": expiry_timestamp,
                    "isStartAfterFirstUse": is_start_after_first_use,
                    "totalGB": total_gb,
                    "totalGB_formatted": format_bytes(total_gb) if total_gb > 0 else "Unlimited",
                    "remaining_bytes": remaining_bytes,
                    "remaining_formatted": format_bytes(remaining_bytes) if total_gb > 0 else "Unlimited",
                    "traffic": format_bytes(client_up + client_down),
                    "up": format_bytes(client_up),
                    "down": format_bytes(client_down),
                    "up_raw": client_up,
                    "down_raw": client_down,
                    "link": link,
                    "inbound_id": inbound.get('id'),
                    "server_id": server.id
                }
                
                processed_clients.append(client_data)
            
            up = inbound.get('up', 0)
            down = inbound.get('down', 0)
            total_upload += up
            total_download += down
            total_clients += len(clients)
            
            for client in clients:
                if client.get('enable', True):
                    active_clients += 1
                else:
                    inactive_clients += 1
            
            if inbound.get('enable', False):
                active_inbounds += 1
            
            stream_settings = json.loads(inbound.get('streamSettings', '{}'))
            network = stream_settings.get('network', 'tcp')
            security = stream_settings.get('security', 'none')
            
            processed.append({
                "id": inbound.get('id'),
                "remark": inbound.get('remark', 'Unnamed'),
                "port": inbound.get('port'),
                "protocol": inbound.get('protocol', 'unknown').upper(),
                "network": network,
                "security": security,
                "total_up": format_bytes(up),
                "total_down": format_bytes(down),
                "total_traffic": format_bytes(up + down),
                "clients": processed_clients,
                "client_count": len(clients),
                "enable": inbound.get('enable', False),
                "expiryTime": format_remaining_days(inbound.get('expiryTime', 0))['text'],
                "server_id": server.id,
                "server_name": server.name
            })
        except Exception as e:
            print(f"Error parsing inbound {inbound.get('id', 'unknown')}: {e}")
            continue
    
    stats = {
        "total_inbounds": len(inbounds),
        "active_inbounds": active_inbounds,
        "total_clients": total_clients,
        "active_clients": active_clients,
        "inactive_clients": inactive_clients,
        "total_upload": format_bytes(total_upload),
        "total_download": format_bytes(total_download),
        "total_traffic": format_bytes(total_upload + total_download),
        "upload_raw": total_upload,
        "download_raw": total_download
    }
    
    return processed, stats

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        data = request.form if request.form else request.json
        username = data.get('username', '')
        password = data.get('password', '')
        
        admin = Admin.query.filter_by(username=username, enabled=True).first()
        
        if admin and admin.check_password(password):
            session.permanent = True
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session['is_superadmin'] = admin.is_superadmin
            
            admin.last_login = datetime.utcnow()
            db.session.commit()
            
            if request.is_json:
                return jsonify({"success": True})
            return redirect(url_for('dashboard'))
        
        if request.is_json:
            return jsonify({"success": False, "error": "Invalid username or password"})
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    servers = Server.query.filter_by(enabled=True).all()
    return render_template('dashboard.html', 
                         servers=servers, 
                         server_count=len(servers),
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False))

@app.route('/servers')
@login_required
def servers_page():
    return render_template('servers.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False))

@app.route('/admins')
@login_required
def admins_page():
    if not session.get('is_superadmin'):
        return redirect(url_for('dashboard'))
    return render_template('admins.html',
                         admin_username=session.get('admin_username'),
                         is_superadmin=session.get('is_superadmin', False))

@app.route('/api/admins', methods=['GET'])
@superadmin_required
def get_admins():
    admins = Admin.query.all()
    return jsonify([a.to_dict() for a in admins])

@app.route('/api/admins', methods=['POST'])
@superadmin_required
def add_admin():
    data = request.json
    
    if not data.get('username') or not data.get('password'):
        return jsonify({"success": False, "error": "Username and password are required"})
    
    if Admin.query.filter_by(username=data['username']).first():
        return jsonify({"success": False, "error": "Username already exists"})
    
    admin = Admin(
        username=data['username'],
        is_superadmin=data.get('is_superadmin', False),
        enabled=data.get('enabled', True)
    )
    admin.set_password(data['password'])
    
    db.session.add(admin)
    db.session.commit()
    
    return jsonify({"success": True, "admin": admin.to_dict()})

@app.route('/api/admins/<int:admin_id>', methods=['PUT'])
@superadmin_required
def update_admin(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    data = request.json
    
    if data.get('username') and data['username'] != admin.username:
        if Admin.query.filter_by(username=data['username']).first():
            return jsonify({"success": False, "error": "Username already exists"})
        admin.username = data['username']
    
    if data.get('password'):
        admin.set_password(data['password'])
    
    if 'is_superadmin' in data:
        admin.is_superadmin = data['is_superadmin']
    
    if 'enabled' in data:
        admin.enabled = data['enabled']
    
    db.session.commit()
    return jsonify({"success": True, "admin": admin.to_dict()})

@app.route('/api/admins/<int:admin_id>', methods=['DELETE'])
@superadmin_required
def delete_admin(admin_id):
    admin = Admin.query.get_or_404(admin_id)
    
    if admin.id == session.get('admin_id'):
        return jsonify({"success": False, "error": "Cannot delete your own account"})
    
    db.session.delete(admin)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers', methods=['GET'])
@login_required
def get_servers():
    servers = Server.query.all()
    return jsonify([s.to_dict() for s in servers])

@app.route('/api/servers', methods=['POST'])
@login_required
def add_server():
    data = request.json
    
    if not data.get('name') or not data.get('host') or not data.get('username') or not data.get('password'):
        return jsonify({"success": False, "error": "All fields are required"})
    
    server = Server(
        name=data['name'],
        host=data['host'].rstrip('/'),
        username=data['username'],
        password=data['password'],
        enabled=data.get('enabled', True),
        panel_type=data.get('panel_type', 'auto')
    )
    
    db.session.add(server)
    db.session.commit()
    
    return jsonify({"success": True, "server": server.to_dict()})

@app.route('/api/servers/<int:server_id>', methods=['PUT'])
@login_required
def update_server(server_id):
    server = Server.query.get_or_404(server_id)
    data = request.json
    
    if data.get('name'):
        server.name = data['name']
    if data.get('host'):
        server.host = data['host'].rstrip('/')
    if data.get('username'):
        server.username = data['username']
    if data.get('password'):
        server.password = data['password']
    if 'enabled' in data:
        server.enabled = data['enabled']
    if data.get('panel_type'):
        server.panel_type = data['panel_type']
    
    db.session.commit()
    return jsonify({"success": True, "server": server.to_dict()})

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>/test', methods=['POST'])
@login_required
def test_server(server_id):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    detected_type = detect_panel_type(session_obj, server.host)
    
    if server.panel_type == 'auto' and detected_type != 'unknown':
        server.panel_type = detected_type
        db.session.commit()
    
    return jsonify({
        "success": True, 
        "message": "Connection successful",
        "panel_type": detected_type
    })

@app.route('/api/add-client', methods=['POST'])
@login_required
def add_client():
    data = request.json
    server_id = data.get('server_id')
    inbound_id = data.get('inbound_id')
    email = data.get('email', '').strip()
    client_id = data.get('client_id', '').strip() if data.get('client_id') else None
    
    if not server_id or not inbound_id or not email:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": f"Connection failed: {error}"})
    
    try:
        # Check for duplicate email across all inbounds in this server
        if server.panel_type == 'sanaei':
            url = f"{server.host}/panel/api/inbounds/list"
        else:
            url = f"{server.host}/xui/API/inbounds/"
        
        response = session_obj.get(url, verify=False, timeout=10)
        inbounds = response.json().get('obj', []) if server.panel_type == 'sanaei' else response.json().get('obj', [])
        
        for inbound in inbounds:
            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            for client in clients:
                if client.get('email') == email:
                    return jsonify({"success": False, "error": f"Email '{email}' already exists on this server"})
        
        # Create new client
        new_client = {
            "email": email,
            "enable": True,
            "expiryTime": 0,
            "totalGB": 0,
            "reset": 0
        }
        
        if client_id:
            new_client["password"] = client_id  # For Trojan
            new_client["id"] = client_id  # For VLESS/VMESS
        
        if server.panel_type == 'sanaei':
            url = f"{server.host}/panel/api/inbounds/addClient"
            payload = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [new_client]})
            }
        else:
            url = f"{server.host}/xui/API/inbounds/addClient/"
            payload = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [new_client]})
            }
        
        response = session_obj.post(url, json=payload, verify=False, timeout=10)
        
        if response.status_code == 200:
            return jsonify({"success": True, "message": f"Client '{email}' created successfully"})
        else:
            return jsonify({"success": False, "error": f"Failed to create client: {response.text}"})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/refresh')
@login_required
def api_refresh():
    servers = Server.query.filter_by(enabled=True).all()
    
    all_inbounds = []
    total_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,
        "active_clients": 0,
        "inactive_clients": 0,
        "upload_raw": 0,
        "download_raw": 0
    }
    server_results = []
    
    for server in servers:
        session_obj, error = get_xui_session(server)
        
        if error:
            server_results.append({
                "server_id": server.id,
                "server_name": server.name,
                "success": False,
                "error": error
            })
            continue
        
        if server.panel_type == 'auto':
            detected = detect_panel_type(session_obj, server.host)
            if detected != 'unknown':
                server.panel_type = detected
                db.session.commit()
        
        inbounds, fetch_error = fetch_inbounds(session_obj, server.host, server.panel_type)
        
        if fetch_error:
            server_results.append({
                "server_id": server.id,
                "server_name": server.name,
                "success": False,
                "error": fetch_error
            })
            continue
        
        processed_inbounds, stats = process_inbounds(inbounds, server)
        all_inbounds.extend(processed_inbounds)
        
        total_stats["total_inbounds"] += stats["total_inbounds"]
        total_stats["active_inbounds"] += stats["active_inbounds"]
        total_stats["total_clients"] += stats["total_clients"]
        total_stats["active_clients"] += stats["active_clients"]
        total_stats["inactive_clients"] += stats["inactive_clients"]
        total_stats["upload_raw"] += stats["upload_raw"]
        total_stats["download_raw"] += stats["download_raw"]
        
        server_results.append({
            "server_id": server.id,
            "server_name": server.name,
            "success": True,
            "stats": stats,
            "panel_type": server.panel_type
        })
    
    total_stats["total_upload"] = format_bytes(total_stats["upload_raw"])
    total_stats["total_download"] = format_bytes(total_stats["download_raw"])
    total_stats["total_traffic"] = format_bytes(total_stats["upload_raw"] + total_stats["download_raw"])
    
    return jsonify({
        "success": True,
        "inbounds": all_inbounds,
        "stats": total_stats,
        "servers": server_results,
        "server_count": len(servers)
    })

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/toggle', methods=['POST'])
@login_required
def toggle_client(server_id, inbound_id, email):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    data = request.json or {}
    enable = data.get('enable', False)
    
    try:
        if server.panel_type == 'sanaei':
            url = f"{server.host}/panel/api/inbounds/{inbound_id}/updateClient/{email}"
        else:
            url = f"{server.host}/panel/api/inbounds/updateClient/{email}"
        
        resp = session_obj.post(url, json={"enable": enable}, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        url = f"{server.host}/panel/api/inbounds/{inbound_id}/updateClient/{email}"
        resp = session_obj.post(url, json={"enable": enable}, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        return jsonify({"success": False, "error": "Failed to update client"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/reset', methods=['POST'])
@login_required
def reset_client_traffic(server_id, inbound_id, email):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    try:
        url = f"{server.host}/panel/api/inbounds/{inbound_id}/resetClientTraffic/{email}"
        resp = session_obj.post(url, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        return jsonify({"success": False, "error": "Failed to reset traffic"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/renew', methods=['POST'])
@login_required
def renew_client(server_id, inbound_id, email):
    server = Server.query.get_or_404(server_id)
    session_obj, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    data = request.json or {}
    days = int(data.get('days', 30))
    volume_gb = int(data.get('volume_gb', 0))
    start_after_first_use = bool(data.get('start_after_first_use', False))
    
    # When start_after_first_use is enabled, allow days=0 (expiry starts after first connection)
    # Otherwise, days must be at least 1
    if start_after_first_use:
        if days < 0 or days > 3650:
            return jsonify({"success": False, "error": "Days must be between 0 and 3650"})
    else:
        if days < 1 or days > 3650:
            return jsonify({"success": False, "error": "Days must be between 1 and 3650"})
    
    if volume_gb < 0 or volume_gb > 10000:
        return jsonify({"success": False, "error": "Volume must be between 0 and 10000 GB"})
    
    try:
        if server.panel_type == 'alireza':
            get_url = f"{server.host}/xui/inbound/get/{inbound_id}"
        else:
            get_url = f"{server.host}/panel/api/inbounds/get/{inbound_id}"
        
        get_resp = session_obj.get(get_url, verify=False, timeout=10)
        
        if get_resp.status_code != 200:
            return jsonify({"success": False, "error": "Failed to get inbound data"})
        
        resp_json = get_resp.json()
        inbound_data = resp_json.get('obj', resp_json.get('data', {}))
        settings = json.loads(inbound_data.get('settings', '{}'))
        clients = settings.get('clients', [])
        
        client_found = None
        for client in clients:
            if client.get('email') == email:
                client_found = client
                break
        
        if not client_found:
            return jsonify({"success": False, "error": "Client not found"})
        
        if start_after_first_use:
            # For "Start After First Use", use negative timestamp
            # Formula: -(days * 86400000) where 86400000 is milliseconds per day
            # X-UI panel converts this to positive timestamp after first connection
            new_expiry = -1 * (days * 86400000)
            client_found['reset'] = 0
        else:
            new_expiry = int((datetime.now() + timedelta(days=days)).timestamp() * 1000)
            client_found['reset'] = 0
        
        client_found['expiryTime'] = new_expiry
        
        if volume_gb > 0:
            client_found['totalGB'] = volume_gb * 1024 * 1024 * 1024
        
        client_found['enable'] = True
        
        uuid = client_found.get('id', client_found.get('password', ''))
        
        if server.panel_type == 'alireza':
            update_data = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [client_found]})
            }
            update_url = f"{server.host}/xui/inbound/updateClient/{uuid}"
        else:
            update_data = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [client_found]})
            }
            update_url = f"{server.host}/panel/api/inbounds/updateClient/{uuid}"
        
        update_resp = session_obj.post(update_url, json=update_data, verify=False, timeout=10)
        
        if update_resp.status_code == 200:
            resp_data = update_resp.json()
            if resp_data.get('success'):
                # After renewal, reset traffic to prevent disconnection due to depleted quota
                try:
                    reset_url = f"{server.host}/panel/api/inbounds/{inbound_id}/resetClientTraffic/{email}"
                    session_obj.post(reset_url, verify=False, timeout=10)
                except:
                    pass  # Reset failure is not critical, renewal still succeeded
                
                return jsonify({"success": True})
            return jsonify({"success": False, "error": resp_data.get('msg', 'Update failed')})
        
        return jsonify({"success": False, "error": "Failed to renew client"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/client/qrcode')
@login_required
def get_qrcode():
    link = request.args.get('link', '')
    
    if not link:
        return jsonify({"success": False, "error": "No link provided"})
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(link)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        img_b64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return jsonify({"success": True, "qrcode": f"data:image/png;base64,{img_b64}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host='0.0.0.0', port=5000, debug=True)
