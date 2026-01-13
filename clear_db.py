from app import app, db, User, Document, DocumentLink
from werkzeug.security import generate_password_hash

with app.app_context():
    # Remove links first, then documents, then users
    DocumentLink.query.delete()
    Document.query.delete()
    User.query.delete()
    db.session.commit()

    print("Cleared all rows from DocumentLink, Document, and User tables.")

    # Recreate default admin account so the app remains accessible
    admin = User(
        username='admin',
        password_hash=generate_password_hash('admin123'),
        role='admin',
        department='Administration'
    )
    db.session.add(admin)
    db.session.commit()
    print('Recreated default admin: username=admin password=admin123')
