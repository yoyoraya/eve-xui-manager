from app import app, db, Admin, get_reseller_access_maps

with app.app_context():
    reseller = Admin.query.filter_by(role='reseller').first()
    if reseller:
        print(f'Reseller: {reseller.username}')
        print(f'Raw allowed_servers: {repr(reseller.allowed_servers)}')
        allowed_map, assignments = get_reseller_access_maps(reseller)
        print(f'Allowed map: {allowed_map}')
        print(f'Assignments: {dict(assignments)}')
    else:
        print('No reseller found')
