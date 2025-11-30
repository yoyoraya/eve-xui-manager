import os
import io
import json
import base64
import requests
import qrcode
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///servers.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'username': self.username,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

with app.app_context():
    db.create_all()

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

def format_date(timestamp):
    if timestamp == 0 or timestamp is None:
        return "Unlimited"
    try:
        return datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M')
    except:
        return "Invalid Date"

def get_xui_session(server):
    session = requests.Session()
    login_url = f"{server.host}/login"
    login_data = {
        "username": server.username,
        "password": server.password
    }
    
    try:
        login_resp = session.post(login_url, data=login_data, verify=False, timeout=10)
        
        if login_resp.status_code == 200:
            resp_json = login_resp.json()
            if resp_json.get('success'):
                return session, None
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

def fetch_inbounds(session, host):
    api_endpoints = [
        "/panel/api/inbounds/list",
        "/xui/inbound/list",
        "/panel/inbound/list"
    ]
    
    for endpoint in api_endpoints:
        try:
            list_url = f"{host}{endpoint}"
            list_resp = session.get(list_url, verify=False, timeout=10)
            
            if list_resp.status_code == 200:
                data = list_resp.json()
                if data.get('success'):
                    return data.get('obj', []), None
        except:
            continue
    
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
    active_inbounds = 0
    
    for inbound in inbounds:
        try:
            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            
            client_stats = inbound.get('clientStats', [])
            
            processed_clients = []
            for client in clients:
                link = generate_client_link(client, inbound, server.host)
                
                client_data = {
                    "email": client.get('email', 'N/A'),
                    "id": client.get('id', client.get('password', 'N/A')),
                    "enable": client.get('enable', True),
                    "expiryTime": format_date(client.get('expiryTime', 0)),
                    "expiryTimestamp": client.get('expiryTime', 0),
                    "totalGB": client.get('totalGB', 0),
                    "link": link,
                    "inbound_id": inbound.get('id'),
                    "server_id": server.id
                }
                
                for stat in client_stats:
                    if stat.get('email') == client.get('email'):
                        client_data['up'] = format_bytes(stat.get('up', 0))
                        client_data['down'] = format_bytes(stat.get('down', 0))
                        client_data['up_raw'] = stat.get('up', 0)
                        client_data['down_raw'] = stat.get('down', 0)
                        client_data['total'] = stat.get('total', 0)
                        break
                else:
                    client_data['up'] = "0 B"
                    client_data['down'] = "0 B"
                    client_data['up_raw'] = 0
                    client_data['down_raw'] = 0
                    client_data['total'] = 0
                
                processed_clients.append(client_data)
            
            up = inbound.get('up', 0)
            down = inbound.get('down', 0)
            total_upload += up
            total_download += down
            total_clients += len(clients)
            
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
                "expiryTime": format_date(inbound.get('expiryTime', 0)),
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
        "total_upload": format_bytes(total_upload),
        "total_download": format_bytes(total_download),
        "total_traffic": format_bytes(total_upload + total_download),
        "upload_raw": total_upload,
        "download_raw": total_download
    }
    
    return processed, stats

@app.route('/')
def dashboard():
    servers = Server.query.filter_by(enabled=True).all()
    return render_template('dashboard.html', servers=servers, server_count=len(servers))

@app.route('/api/servers', methods=['GET'])
def get_servers():
    servers = Server.query.all()
    return jsonify([s.to_dict() for s in servers])

@app.route('/api/servers', methods=['POST'])
def add_server():
    data = request.json
    
    if not data.get('name') or not data.get('host') or not data.get('username') or not data.get('password'):
        return jsonify({"success": False, "error": "All fields are required"})
    
    server = Server(
        name=data['name'],
        host=data['host'].rstrip('/'),
        username=data['username'],
        password=data['password'],
        enabled=data.get('enabled', True)
    )
    
    db.session.add(server)
    db.session.commit()
    
    return jsonify({"success": True, "server": server.to_dict()})

@app.route('/api/servers/<int:server_id>', methods=['PUT'])
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
    
    db.session.commit()
    return jsonify({"success": True, "server": server.to_dict()})

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/servers/<int:server_id>/test', methods=['POST'])
def test_server(server_id):
    server = Server.query.get_or_404(server_id)
    session, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    return jsonify({"success": True, "message": "Connection successful"})

@app.route('/api/refresh')
def api_refresh():
    servers = Server.query.filter_by(enabled=True).all()
    
    all_inbounds = []
    total_stats = {
        "total_inbounds": 0,
        "active_inbounds": 0,
        "total_clients": 0,
        "upload_raw": 0,
        "download_raw": 0
    }
    server_results = []
    
    for server in servers:
        session, error = get_xui_session(server)
        
        if error:
            server_results.append({
                "server_id": server.id,
                "server_name": server.name,
                "success": False,
                "error": error
            })
            continue
        
        inbounds, fetch_error = fetch_inbounds(session, server.host)
        
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
        total_stats["upload_raw"] += stats["upload_raw"]
        total_stats["download_raw"] += stats["download_raw"]
        
        server_results.append({
            "server_id": server.id,
            "server_name": server.name,
            "success": True,
            "stats": stats
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
def toggle_client(server_id, inbound_id, email):
    server = Server.query.get_or_404(server_id)
    session, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    data = request.json or {}
    enable = data.get('enable', False)
    
    try:
        url = f"{server.host}/panel/api/inbounds/updateClient/{email}"
        resp = session.post(url, json={"enable": enable}, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        url = f"{server.host}/panel/api/inbounds/{inbound_id}/updateClient/{email}"
        resp = session.post(url, json={"enable": enable}, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        return jsonify({"success": False, "error": "Failed to update client"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/client/<int:server_id>/<int:inbound_id>/<email>/reset', methods=['POST'])
def reset_client_traffic(server_id, inbound_id, email):
    server = Server.query.get_or_404(server_id)
    session, error = get_xui_session(server)
    
    if error:
        return jsonify({"success": False, "error": error})
    
    try:
        url = f"{server.host}/panel/api/inbounds/{inbound_id}/resetClientTraffic/{email}"
        resp = session.post(url, verify=False, timeout=10)
        
        if resp.status_code == 200 and resp.json().get('success'):
            return jsonify({"success": True})
        
        return jsonify({"success": False, "error": "Failed to reset traffic"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/client/qrcode')
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
