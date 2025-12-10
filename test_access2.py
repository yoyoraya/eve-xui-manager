from app import app, is_inbound_accessible

with app.app_context():
    allowed_map = {1: {7, 8, 9}}
    assignments = {1: {1}}
    
    print('Allowed map:', allowed_map)
    print('Assignments:', assignments)
    print()
    
    test_inbounds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    
    for inb_id in test_inbounds:
        result = is_inbound_accessible(1, inb_id, allowed_map, assignments)
        print(f'Inbound {inb_id}: {result}')
