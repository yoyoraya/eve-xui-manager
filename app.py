import os
import json
import requests
from datetime import datetime
from flask import Flask, render_template, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

XUI_HOST = os.environ.get("XUI_HOST", "")
XUI_USERNAME = os.environ.get("XUI_USERNAME", "")
XUI_PASSWORD = os.environ.get("XUI_PASSWORD", "")

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

def get_xui_session():
    if not XUI_HOST or not XUI_USERNAME or not XUI_PASSWORD:
        return None, "Server credentials not configured. Please set XUI_HOST, XUI_USERNAME, and XUI_PASSWORD in environment variables."
    
    session = requests.Session()
    login_url = f"{XUI_HOST}/login"
    login_data = {
        "username": XUI_USERNAME,
        "password": XUI_PASSWORD
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
        return None, "Cannot connect to X-UI server. Please check the host address."
    except requests.exceptions.Timeout:
        return None, "Connection to X-UI server timed out."
    except Exception as e:
        return None, f"Error connecting to server: {str(e)}"

def fetch_inbounds(session):
    api_endpoints = [
        "/panel/api/inbounds/list",
        "/xui/inbound/list",
        "/panel/inbound/list"
    ]
    
    for endpoint in api_endpoints:
        try:
            list_url = f"{XUI_HOST}{endpoint}"
            list_resp = session.get(list_url, verify=False, timeout=10)
            
            if list_resp.status_code == 200:
                data = list_resp.json()
                if data.get('success'):
                    return data.get('obj', []), None
        except:
            continue
    
    return None, "Failed to fetch inbounds. API endpoint not found."

def process_inbounds(inbounds):
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
                client_data = {
                    "email": client.get('email', 'N/A'),
                    "id": client.get('id', client.get('password', 'N/A')),
                    "enable": client.get('enable', True),
                    "expiryTime": format_date(client.get('expiryTime', 0)),
                    "totalGB": client.get('totalGB', 0),
                }
                
                for stat in client_stats:
                    if stat.get('email') == client.get('email'):
                        client_data['up'] = format_bytes(stat.get('up', 0))
                        client_data['down'] = format_bytes(stat.get('down', 0))
                        client_data['total'] = stat.get('total', 0)
                        break
                else:
                    client_data['up'] = "0 B"
                    client_data['down'] = "0 B"
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
                "expiryTime": format_date(inbound.get('expiryTime', 0))
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
        "total_traffic": format_bytes(total_upload + total_download)
    }
    
    return processed, stats

@app.route('/')
def dashboard():
    session, error = get_xui_session()
    
    if error:
        return render_template('dashboard.html', 
                             error=error, 
                             inbounds=[], 
                             stats=None,
                             connected=False)
    
    inbounds, fetch_error = fetch_inbounds(session)
    
    if fetch_error:
        return render_template('dashboard.html', 
                             error=fetch_error, 
                             inbounds=[], 
                             stats=None,
                             connected=False)
    
    processed_inbounds, stats = process_inbounds(inbounds)
    
    return render_template('dashboard.html', 
                         inbounds=processed_inbounds, 
                         stats=stats,
                         error=None,
                         connected=True,
                         host=XUI_HOST)

@app.route('/api/refresh')
def api_refresh():
    session, error = get_xui_session()
    
    if error:
        return jsonify({"success": False, "error": error})
    
    inbounds, fetch_error = fetch_inbounds(session)
    
    if fetch_error:
        return jsonify({"success": False, "error": fetch_error})
    
    processed_inbounds, stats = process_inbounds(inbounds)
    
    return jsonify({
        "success": True,
        "inbounds": processed_inbounds,
        "stats": stats
    })

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(host='0.0.0.0', port=5000, debug=True)
