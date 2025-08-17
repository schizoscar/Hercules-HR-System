from HerculesSystem import app, db, Employee

with app.app_context():
    # Create folder if doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    db.create_all()
    
    # Check if user already exists
    if not Employee.query.filter_by(email='admin@example.com').first():
        test_user = Employee(
            username='admin',
            password='temp_password',
            full_name='Admin User',
            email='admin@example.com',
            department='IT',
            position='Administrator'
        )
        db.session.add(test_user)
        db.session.commit()
        print("Test user created!")
    else:
        print("Test user already exists")