from app import app, parse_allowed_servers, resolve_allowed_map

with app.app_context():
    raw = '[{"server_id": 1, "inbounds": [7, 8, 9]}]'
    print('Raw:', raw)
    print('Parsed:', parse_allowed_servers(raw))
    print('Resolved map:', resolve_allowed_map(raw))
