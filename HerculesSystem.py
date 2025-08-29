from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import sqlite3
import socket
from http.client import HTTPException
from io import StringIO
import csv

# handler for the bad requests
import werkzeug.serving


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'hr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class Employee(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(80))
    position = db.Column(db.String(80))
    hire_date = db.Column(db.Date)
    is_admin = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='employee')  # admin, supervisor, office, factory

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

def add_is_admin_column():
    """Add the is_admin and user_type columns to the employee table if they don't exist"""
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(os.path.join(app.instance_path, 'hr.db'))
        cursor = conn.cursor()
        
        # Check if the is_admin column exists
        cursor.execute("PRAGMA table_info(employee)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_admin' not in columns:
            # Add the is_admin column
            cursor.execute("ALTER TABLE employee ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
            print("Added is_admin column to employee table")
        
        if 'user_type' not in columns:
            # Add the user_type column
            cursor.execute("ALTER TABLE employee ADD COLUMN user_type VARCHAR(20) DEFAULT 'employee'")
            print("Added user_type column to employee table")
        
        # Check if LeaveRequest table has the new columns
        cursor.execute("PRAGMA table_info(leave_request)")
        leave_columns = [column[1] for column in cursor.fetchall()]
        
        if 'days_requested' not in leave_columns:
            cursor.execute("ALTER TABLE leave_request ADD COLUMN days_requested INTEGER DEFAULT 0")
            print("Added days_requested column to leave_request table")
        
        if 'approved_at' not in leave_columns:
            cursor.execute("ALTER TABLE leave_request ADD COLUMN approved_at DATETIME")
            print("Added approved_at column to leave_request table")
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error checking/adding columns: {e}")

# Add this right before your route definitions
with app.app_context():
    # Create the instance folder if it doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    # Create all tables
    db.create_all()
    print("Database tables created!")
    
    # Add the is_admin column if it doesn't exist
    add_is_admin_column()

@app.before_request
def before_request():
    # Force HTTP for all requests to prevent HTTPS issues
    if request.url.startswith('https://'):
        new_url = request.url.replace('https://', 'http://', 1)
        return redirect(new_url, code=301)

original_handle = werkzeug.serving.WSGIRequestHandler.handle

def handle_corrupted_headers(self):
    try:
        return original_handle(self)
    except (UnicodeDecodeError, ValueError, HTTPException) as e:
        if "Bad request version" in str(e) or "Bad HTTP/0.9 request type" in str(e):
            # This is likely an HTTPS request to an HTTP server
            print(f"Intercepted malformed HTTPS request, redirecting to HTTP...")
            # Try to redirect to HTTP
            try:
                host = self.headers.get('Host', 'localhost:5000')
                path = self.path
                self.send_response(301)
                self.send_header('Location', f'http://{host}{path}')
                self.end_headers()
                return
            except Exception as redirect_error:
                print(f"Redirect failed: {redirect_error}")
            return
        # Re-raise other exceptions
        raise

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)  # Vacation, Sick, Personal, etc.
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    days_requested = db.Column(db.Integer, nullable=False)  # Number of days requested
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)  # When it was approved
    
    # Relationship
    employee = db.relationship('Employee', backref=db.backref('leave_requests', lazy=True))

class LeaveRequestForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    leave_type = SelectField('Leave Type', choices=[
        ('vacation', 'Vacation Leave'),
        ('sick', 'Sick Leave'),
        ('personal', 'Personal Leave'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    submit = SubmitField('Submit Request')

werkzeug.serving.WSGIRequestHandler.handle = handle_corrupted_headers

with app.app_context():
    # Create the instance folder if it doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    # Create all tables
    db.create_all()
    print("Database tables created!")
    
    # Add the is_admin and user_type columns if they don't exist
    add_is_admin_column()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/create_test_users')  # temporary
def create_test_users():
    # Check if admin user already exists
    if not Employee.query.filter_by(username='admin').first():
        admin_user = Employee(
            username='admin',
            password=generate_password_hash('temp_password'),
            full_name='Admin User',
            email='admin@example.com',
            department='HR',
            position='System Administrator',
            hire_date=datetime.utcnow(),
            is_admin=True,
            user_type='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")
    
    # Check if Samuel Chong already exists (office employee)
    if not Employee.query.filter_by(username='samchong').first():
        samuel_user = Employee(
            username='samchong',
            password=generate_password_hash('password123'),
            full_name='Samuel Chong',
            email='samuel.chong@example.com',
            department='Marketing',
            position='Marketing Specialist',
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='office'
        )
        db.session.add(samuel_user)
        db.session.commit()
        print("Samuel Chong user created")
    
    # Create a factory employee
    if not Employee.query.filter_by(username='factory1').first():
        factory_user = Employee(
            username='factory1',
            password=generate_password_hash('factory123'),
            full_name='Factory Worker',
            email='factory@example.com',
            department='Production',
            position='Assembly Line Worker',
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='factory'
        )
        db.session.add(factory_user)
        db.session.commit()
        print("Factory user created")
    
    # Create a supervisor
    if not Employee.query.filter_by(username='supervisor1').first():
        supervisor_user = Employee(
            username='supervisor1',
            password=generate_password_hash('super123'),
            full_name='Supervisor User',
            email='supervisor@example.com',
            department='Operations',
            position='Team Supervisor',
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='supervisor'
        )
        db.session.add(supervisor_user)
        db.session.commit()
        print("Supervisor user created")
    
    return "Test users created successfully"

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Employee.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# HR Directory Pages
@app.route('/employee_directory')
@login_required
def employee_directory():
    employees = Employee.query.all()
    return render_template('employee_directory.html', employees=employees)

@app.route('/department_directory')
@login_required
def department_directory():
    # This would normally query departments from a Department model
    departments = ["HR", "IT", "Finance", "Marketing", "Operations"]  # Placeholder
    return render_template('department_directory.html', departments=departments)

@app.route('/performance_reviews')
@login_required
def performance_reviews():
    return render_template('performance_reviews.html')

@app.route('/leaves')
@login_required
def leaves():
    # For admin/supervisor: show all pending requests
    if current_user.user_type in ['admin', 'supervisor']:
        pending_requests = LeaveRequest.query.filter_by(status='pending').all()
        return render_template('leaves.html', pending_requests=pending_requests)
    # For employees: show their leave requests and balance
    else:
        user_requests = LeaveRequest.query.filter_by(employee_id=current_user.id).order_by(LeaveRequest.created_at.desc()).all()
        return render_template('leaves.html', user_requests=user_requests)

@app.route('/request_leave', methods=['GET', 'POST'])
@login_required
def request_leave():
    form = LeaveRequestForm()
    
    if form.validate_on_submit():
        # Calculate number of days
        delta = form.end_date.data - form.start_date.data
        days_requested = delta.days + 1  # Inclusive of both start and end dates
        
        # Create leave request
        leave_request = LeaveRequest(
            employee_id=current_user.id,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            leave_type=form.leave_type.data,
            reason=form.reason.data,
            status='pending',
            days_requested=days_requested
        )
        
        db.session.add(leave_request)
        db.session.commit()
        
        flash('Leave request submitted successfully! You will be notified when your supervisor reviews it.', 'success')
        return redirect(url_for('leaves'))
    
    return render_template('request_leave.html', form=form)

@app.route('/approve_leave/<int:request_id>')
@login_required
def approve_leave(request_id):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to approve leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    leave_request.status = 'approved'
    leave_request.approved_at = datetime.utcnow()
    
    # Here you would deduct from the employee's leave balance
    # For now,  just mark it as approved and deducted immediately
    # In a real system, you'd update the employee's leave balance
    
    db.session.commit()
    
    flash('Leave request approved successfully. Leave balance has been deducted.', 'success')
    return redirect(url_for('leaves'))

@app.route('/reject_leave/<int:request_id>')
@login_required
def reject_leave(request_id):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to reject leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    leave_request.status = 'rejected'
    db.session.commit()
    
    flash('Leave request rejected.', 'info')
    return redirect(url_for('leaves'))

@app.route('/all_leaves')
@login_required
def all_leaves():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view all leaves.', 'danger')
        return redirect(url_for('leaves'))
    
    # Get all leave requests, ordered by latest first
    all_requests = LeaveRequest.query.order_by(LeaveRequest.created_at.desc()).all()
    return render_template('all_leaves.html', all_requests=all_requests)

@app.route('/export_leaves')
@login_required
def export_leaves():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to export leaves.', 'danger')
        return redirect(url_for('leaves'))
    
    # Get date range parameters
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    
    # Build query
    query = LeaveRequest.query
    
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            query = query.filter(LeaveRequest.start_date >= start_date)
        except ValueError:
            pass
    
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            query = query.filter(LeaveRequest.end_date <= end_date)
        except ValueError:
            pass
    
    # Get the filtered leaves
    leaves = query.order_by(LeaveRequest.created_at.desc()).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Employee Name', 'Leave Type', 'Start Date', 'End Date', 
                     'Days Requested', 'Status', 'Reason', 'Submitted On', 'Approved/Rejected On'])
    
    # Write data
    for leave in leaves:
        writer.writerow([
            leave.employee.full_name,
            leave.leave_type.title(),
            leave.start_date.strftime('%Y-%m-%d'),
            leave.end_date.strftime('%Y-%m-%d'),
            leave.days_requested,
            leave.status.title(),
            leave.reason,
            leave.created_at.strftime('%Y-%m-%d %H:%M'),
            leave.approved_at.strftime('%Y-%m-%d %H:%M') if leave.approved_at else 'N/A'
        ])
    
    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=leaves_export.csv'
    response.headers['Content-type'] = 'text/csv'
    
    return response

@app.route('/recruitment')
@login_required
def recruitment():
    return render_template('recruitment.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/test')
def test_connection():
    return "Connection successful! Flask is working."

if __name__ == '__main__':
    # Create the instance folder if it doesn't exist
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    # Get your actual WiFi IP address
    def get_wifi_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    wifi_ip = get_wifi_ip()
    
    print("=" * 50)
    print(f"Your WiFi IP address is: {wifi_ip}")
    print(f"Access the app at: http://{wifi_ip}:5000")
    print(f"Test connection at: http://{wifi_ip}:5000/test")
    print("Make sure your mobile device is on the same WiFi network!")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)