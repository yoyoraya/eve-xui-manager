from app import app, resolve_allowed_map, is_inbound_accessible

with app.app_context():
    raw = '[{"server_id": 1, "inbounds": [7, 8, 9]}]'
    allowed_map = resolve_allowed_map(raw)
    assignments = {}  # No assignments for now
    
    print('Allowed map:', allowed_map)
    print()
    
    # Test inbounds from screenshot: Portal, G12, G13, G14, sample, G15, PT, G16
    # Based on dropdown: Portal=3088[3], G12=16000[0], G13=17000[0], G14=18000[0], sample=58374[0], G15=26000[0], PT=23218[0], G16=18456[0]
    # But we need actual inbound IDs. Let's test with IDs 7, 8, 9 (allowed) and some others
    
    test_inbounds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    
    for inb_id in test_inbounds:
        result = is_inbound_accessible(1, inb_id, allowed_map, assignments)
        print(f'Inbound {inb_id}: {result}')
