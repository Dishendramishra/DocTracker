
from flask import Flask, render_template_string, request, redirect, url_for, send_file, flash, session, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import csv
import io
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///documents.db'  # Change to PostgreSQL: postgresql://user:pass@localhost/dbname
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB max file size
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, user
    department = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    doc_type = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    doc_date = db.Column(db.Date, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    uploader = db.relationship('User', backref='documents')
    linked_from = db.relationship('DocumentLink', foreign_keys='DocumentLink.target_doc_id', backref='target_document')
    linked_to = db.relationship('DocumentLink', foreign_keys='DocumentLink.source_doc_id', backref='source_document')

class DocumentLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_doc_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    target_doc_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    link_type = db.Column(db.String(50))  # "referenced_in", "derived_from", "related_to"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables and default admin user
with app.app_context():
    db.create_all()
    # Create default admin if doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            department='Administration'
        )
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template("LOGIN_TEMPLATE.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Get filter parameters
    search = request.args.get('search', '')
    doc_type = request.args.get('doc_type', '')
    department = request.args.get('department', '')
    
    # Build query
    query = Document.query
    
    if search:
        query = query.filter(
            (Document.original_filename.contains(search)) |
            (Document.description.contains(search))
        )
    
    if doc_type:
        query = query.filter(Document.doc_type == doc_type)
    
    if department:
        query = query.filter(Document.department.contains(department))
    
    documents = query.order_by(Document.upload_date.desc()).all()
    all_documents = Document.query.order_by(Document.upload_date.desc()).all()
    
    # Calculate stats
    total_docs = Document.query.count()
    this_month = Document.query.filter(
        db.func.strftime('%Y-%m', Document.doc_date) == datetime.now().strftime('%Y-%m')
    ).count()
    departments = db.session.query(Document.department).distinct().count()
    my_docs = Document.query.filter_by(uploaded_by=current_user.id).count()
    
    stats = {
        'total': total_docs,
        'this_month': this_month,
        'departments': departments,
        'my_docs': my_docs
    }
    
    return render_template("MAIN_TEMPLATE.html", documents=documents, stats=stats, all_documents=all_documents)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if not file.filename.lower().endswith('.pdf'):
        flash('Only PDF files are allowed', 'error')
        return redirect(url_for('index'))
    
    # Save file with unique name
    original_filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{original_filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Create database entry
    doc = Document(
        filename=filename,
        original_filename=original_filename,
        doc_type=request.form['doc_type'],
        department=request.form['department'],
        doc_date=datetime.strptime(request.form['doc_date'], '%Y-%m-%d').date(),
        description=request.form.get('description', ''),
        uploaded_by=current_user.id
    )
    
    db.session.add(doc)
    db.session.flush()
    
    # Add links to related documents
    linked_doc_ids = request.form.getlist('linked_docs')
    for target_id in linked_doc_ids:
        if target_id:
            link = DocumentLink(
                source_doc_id=doc.id,
                target_doc_id=int(target_id),
                link_type='related_to'
            )
            db.session.add(link)
    
    db.session.commit()
    
    flash(f'Document "{original_filename}" uploaded successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/document/<int:doc_id>')
@login_required
def view_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    all_documents = Document.query.order_by(Document.upload_date.desc()).all()
    return render_template("DOCUMENT_VIEW_TEMPLATE.html", document=document, all_documents=all_documents)

@app.route('/document/<int:doc_id>/add_link', methods=['POST'])
@login_required
def add_link(doc_id):
    target_doc_id = request.form.get('target_doc_id')
    
    if target_doc_id:
        link = DocumentLink(
            source_doc_id=doc_id,
            target_doc_id=int(target_doc_id),
            link_type='related_to'
        )
        db.session.add(link)
        db.session.commit()
        flash('Link added successfully!', 'success')
    
    return redirect(url_for('view_document', doc_id=doc_id))

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    doc = Document.query.get_or_404(doc_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], doc.filename)
    return send_file(filepath, as_attachment=True, download_name=doc.original_filename)

@app.route('/preview/<int:doc_id>')
@login_required
def preview(doc_id):
    doc = Document.query.get_or_404(doc_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], doc.filename)
    return send_file(filepath, mimetype='application/pdf')

@app.route('/delete/<int:doc_id>')
@login_required
def delete(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Check permissions
    if current_user.role != 'admin' and doc.uploaded_by != current_user.id:
        flash('You do not have permission to delete this document', 'error')
        return redirect(url_for('index'))
    
    # Delete links
    DocumentLink.query.filter(
        (DocumentLink.source_doc_id == doc_id) | (DocumentLink.target_doc_id == doc_id)
    ).delete()
    
    # Delete file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], doc.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    
    # Delete database entry
    db.session.delete(doc)
    db.session.commit()
    
    flash(f'Document "{doc.original_filename}" deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_csv():
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['ID', 'Filename', 'Type', 'Department', 'Document Date', 'Upload Date', 'Uploaded By', 'Description', 'Linked Documents'])
    
    # Write data
    documents = Document.query.order_by(Document.upload_date.desc()).all()
    for doc in documents:
        linked = ', '.join([str(link.target_doc_id) for link in doc.linked_to])
        writer.writerow([
            doc.id,
            doc.original_filename,
            doc.doc_type,
            doc.department,
            doc.doc_date.strftime('%Y-%m-%d'),
            doc.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
            doc.uploader.username if doc.uploader else 'N/A',
            doc.description,
            linked
        ])
    
    # Prepare response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'documents_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('index'))
    
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("USERS_TEMPLATE.html", users=all_users)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    username = request.form['username']
    password = request.form['password']
    department = request.form.get('department', '')
    role = request.form['role']
    
    # Check if username exists
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('users'))
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        department=department,
        role=role
    )
    
    db.session.add(user)
    db.session.commit()
    
    flash(f'User "{username}" created successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User "{user.username}" deleted successfully!', 'success')
    return redirect(url_for('users'))

if __name__ == '__main__':
    app.run(debug=True)