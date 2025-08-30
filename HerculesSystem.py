from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import sqlite3
import socket
from http.client import HTTPException
from io import StringIO
import csv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import uuid

# handler for the bad requests
import werkzeug.serving


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'hr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Email configuration - Update these values
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'scarletsumirepoh@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'ipfo egit wyrk uzdb'     # Gmail App Password (not your regular password)
app.config['MAIL_DEFAULT_SENDER'] = 'scarletsumirepoh.email@gmail.com'

# configuration for leave file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'attachments')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def send_email(to_email, subject, body):
    """Send email using SMTP with better error handling"""
    try:
        # Check if email is configured
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            print("Email not configured properly")
            return False
        
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.ehlo()
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], to_email, text)
        server.quit()
        print(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email to {to_email}: {str(e)}")
        return False

def send_leave_status_email(employee, leave_request, status):
    """Send email about leave status"""
    subject = f"Your Leave Request Has Been {status.title()}"
    body = f"""
Dear {employee.full_name},

Your leave request has been {status}.

Details:
- Type: {leave_request.leave_type.title()}
- From: {leave_request.start_date.strftime('%Y-%m-%d')}
- To: {leave_request.end_date.strftime('%Y-%m-%d')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Status: {status.title()}

Thank you,
HR Department
"""
    return send_email(employee.email, subject, body)

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
    
    def generate_temp_password(self):
        """Generate a temporary password"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(8))

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Employee, int(user_id))


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
        
        if 'compassionate_type' not in leave_columns:
            cursor.execute("ALTER TABLE leave_request ADD COLUMN compassionate_type VARCHAR(50)")
            print("Added compassionate_type column to leave_request table")
        
        if 'attachment_filename' not in leave_columns:
            cursor.execute("ALTER TABLE leave_request ADD COLUMN attachment_filename VARCHAR(255)")
            print("Added attachment_filename column to leave_request table")
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error checking/adding columns: {e}")

class AddEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    department = StringField('Department', validators=[DataRequired()])
    position = StringField('Position', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[
        ('office', 'Office Employee'),
        ('factory', 'Factory Worker'),
        ('supervisor', 'Supervisor')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Employee')

class BulkAddEmployeesForm(FlaskForm):
    employee_data = TextAreaField('Employee Data', validators=[DataRequired()], 
        description="Format: Full Name,Email,Department,Position,User Type (one per line)")
    submit = SubmitField('Add Employees')

class EditEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    department = StringField('Department', validators=[DataRequired()])
    position = StringField('Position', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[
        ('office', 'Office Employee'),
        ('factory', 'Factory Worker'),
        ('supervisor', 'Supervisor')
    ], validators=[DataRequired()])
    submit = SubmitField('Update Employee')
    

class ResetPasswordForm(FlaskForm):
    submit = SubmitField('Reset Password')

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
    leave_type = db.Column(db.String(50), nullable=False)
    compassionate_type = db.Column(db.String(50))  # For compassionate leave sub-type
    reason = db.Column(db.Text)
    attachment_filename = db.Column(db.String(255))  # Store filename
    status = db.Column(db.String(20), default='pending')
    days_requested = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    
    # Relationship
    employee = db.relationship('Employee', backref=db.backref('leave_requests', lazy=True))


class LeaveRequestForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    leave_type = SelectField('Leave Type', choices=[
        ('annual', 'Annual Leave'),
        ('medical', 'Medical Leave'),
        ('maternity', 'Maternity Leave (90 days max)'),
        ('compassionate', 'Compassionate Leave'),
        ('marriage', 'Marriage Leave (3 days max)'),
        ('hospitalised', 'Hospitalised Leave (60 days/year max)'),
        ('socso_mc', 'SOCSO MC (No limit)')
    ], validators=[DataRequired()])
    compassionate_type = SelectField('Compassionate Leave Type', choices=[
        ('', 'Select relationship'),
        ('child', 'Child'),
        ('parents', 'Parents'),
        ('husband', 'Husband'),
        ('wife', 'Wife'),
        ('grandparents', 'Grandparents'),
        ('sibling', 'Sibling')
    ], validators=[])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    attachment = FileField('Attachment (if needed)', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx'], 
                   'Only images (JPG, PNG), PDF and Word documents are allowed')
    ])
    submit = SubmitField('Submit Request')

werkzeug.serving.WSGIRequestHandler.handle = handle_corrupted_headers

def validate_leave_days(leave_type, days_requested, compassionate_type=None):
    """Validate leave days based on leave type"""
    max_days = {
        'annual': 365,  # No specific limit for annual leave
        'medical': 60,  # Typically 60 days per year for medical
        'maternity': 90,
        'compassionate': 3 if compassionate_type in ['child', 'parents', 'husband', 'wife'] else 1,
        'marriage': 3,
        'hospitalised': 60,
        'socso_mc': 365  # No limit
    }
    
    if leave_type not in max_days:
        return False, "Invalid leave type"
    
    max_allowed = max_days[leave_type]
    
    if days_requested > max_allowed:
        if leave_type == 'compassionate':
            relationship = "immediate family" if compassionate_type in ['child', 'parents', 'husband', 'wife'] else "extended family"
            return False, f"Compassionate leave for {relationship} is limited to {max_allowed} day(s)"
        else:
            return False, f"{leave_type.replace('_', ' ').title()} leave is limited to {max_allowed} days"
    
    return True, ""

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
    # Factory workers only see leaves management
    if current_user.user_type == 'factory':
        return render_template('factory_dashboard.html')
    
    # Regular dashboard for other users
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
    
    # REMOVE THIS SECTION - let the JavaScript handle the visibility
    # Show/hide compassionate type field based on leave type
    # if request.method == 'GET':
    #     form.compassionate_type.render_kw = {'style': 'display: none;'}
    
    if form.validate_on_submit():
        # Calculate number of days
        delta = form.end_date.data - form.start_date.data
        days_requested = delta.days + 1  # Inclusive of both start and end dates
        
        # Validate leave days
        compassionate_type = form.compassionate_type.data if form.leave_type.data == 'compassionate' else None
        is_valid, error_message = validate_leave_days(
            form.leave_type.data, days_requested, compassionate_type
        )
        
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('request_leave.html', form=form)
        
        # Handle file upload
        attachment_filename = None
        if form.attachment.data:
            # Create upload folder if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Generate unique filename
            filename = secure_filename(form.attachment.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            form.attachment.data.save(file_path)
            attachment_filename = unique_filename
        
        # Create leave request
        leave_request = LeaveRequest(
            employee_id=current_user.id,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            leave_type=form.leave_type.data,
            compassionate_type=compassionate_type,
            reason=form.reason.data,
            attachment_filename=attachment_filename,
            status='pending',
            days_requested=days_requested
        )
        
        # Send notification to admins
        if send_leave_request_notification(leave_request):
            flash('Leave request submitted successfully! Admins have been notified.', 'success')
        else:
            flash('Leave request submitted successfully! Failed to send notification to admins.', 'warning')
        
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
    
    db.session.commit()
    
    # Send email notification
    if send_leave_status_email(leave_request.employee, leave_request, 'approved'):
        flash('Leave request approved successfully. Email notification sent.', 'success')
    else:
        flash('Leave request approved successfully, but failed to send email notification.', 'warning')
    
    return redirect(url_for('leaves'))

@app.route('/reject_leave/<int:request_id>')
@login_required
def reject_leave(request_id):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to reject leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    leave_request.status = 'rejected'
    leave_request.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    # Send email notification
    if send_leave_status_email(leave_request.employee, leave_request, 'rejected'):
        flash('Leave request rejected. Email notification sent.', 'info')
    else:
        flash('Leave request rejected, but failed to send email notification.', 'warning')
    
    return redirect(url_for('leaves'))

@app.route('/manage_employees')
@login_required
def manage_employees():
    if current_user.user_type != 'admin':
        flash('You do not have permission to manage employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    employees = Employee.query.filter(Employee.user_type != 'admin').all()
    return render_template('manage_employees.html', employees=employees)

@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.user_type != 'admin':
        flash('You do not have permission to add employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = AddEmployeeForm()
    
    if form.validate_on_submit():
        # Generate username from email
        username = form.email.data.split('@')[0]
        
        # Check if username already exists
        if Employee.query.filter_by(username=username).first():
            flash('Username already exists. Please use a different email.', 'danger')
            return render_template('add_employee.html', form=form)
        
        # Generate temporary password
        temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
        
        employee = Employee(
            username=username,
            password=generate_password_hash(temp_password),
            full_name=form.full_name.data,
            email=form.email.data,
            department=form.department.data,
            position=form.position.data,
            user_type=form.user_type.data,
            hire_date=datetime.utcnow().date()
        )
        
        db.session.add(employee)
        db.session.commit()
        
        # Send welcome email with credentials
        subject = "Your HR Nexus Account Has Been Created"
        body = f"""
Dear {form.full_name.data},

Your HR Nexus account has been created.

Login details:
Username: {username}
Password: {temp_password}

Please change your password after first login.

You can access the system at: http://your-server-url

Thank you,
HR Department
"""
        if send_email(form.email.data, subject, body):
            flash('Employee added successfully. Login details sent via email.', 'success')
        else:
            flash(f'Employee added successfully. Login details: Username: {username}, Password: {temp_password}. Failed to send email.', 'warning')
        
        return redirect(url_for('manage_employees'))
    
    return render_template('add_employee.html', form=form)

@app.route('/bulk_add_employees', methods=['GET', 'POST'])
@login_required
def bulk_add_employees():
    if current_user.user_type != 'admin':
        flash('You do not have permission to add employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = BulkAddEmployeesForm()
    
    if form.validate_on_submit():
        lines = form.employee_data.data.strip().split('\n')
        success_count = 0
        error_count = 0
        
        for line in lines:
            try:
                data = [item.strip() for item in line.split(',')]
                if len(data) != 5:
                    error_count += 1
                    continue
                
                full_name, email, department, position, user_type = data
                
                # Generate username from email
                username = email.split('@')[0]
                
                # Check if user already exists
                if Employee.query.filter((Employee.username == username) | (Employee.email == email)).first():
                    error_count += 1
                    continue
                
                # Generate temporary password
                temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                
                employee = Employee(
                    username=username,
                    password=generate_password_hash(temp_password),
                    full_name=full_name,
                    email=email,
                    department=department,
                    position=position,
                    user_type=user_type,
                    hire_date=datetime.utcnow().date()
                )
                
                db.session.add(employee)
                success_count += 1
                
                # Send welcome email
                subject = "Your HR Nexus Account Has Been Created"
                body = f"""
Dear {full_name},

Your HR Nexus account has been created.

Login details:
Username: {username}
Password: {temp_password}

Please change your password after first login.

You can access the system at: http://your-server-url

Thank you,
HR Department
"""
                send_email(email, subject, body)
                
            except:
                error_count += 1
        
        db.session.commit()
        flash(f'Added {success_count} employees successfully. {error_count} failed.', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('bulk_add_employees.html', form=form)

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

@app.route('/download_attachment/<filename>')
@login_required
def download_attachment(filename):
    """Serve uploaded attachment files"""
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        flash('Attachment not found.', 'danger')
        return redirect(url_for('leaves'))

@app.route('/edit_employee/<int:employee_id>', methods=['GET', 'POST'])
@login_required
def edit_employee(employee_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to edit employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    employee = Employee.query.get_or_404(employee_id)
    form = EditEmployeeForm(obj=employee)
    
    if form.validate_on_submit():
        # Check if email was changed and if it already exists
        if form.email.data != employee.email:
            existing_employee = Employee.query.filter_by(email=form.email.data).first()
            if existing_employee and existing_employee.id != employee.id:
                flash('Email already exists. Please use a different email.', 'danger')
                return render_template('edit_employee.html', form=form, employee=employee)
        
        # Update employee details
        employee.full_name = form.full_name.data
        employee.email = form.email.data
        employee.department = form.department.data
        employee.position = form.position.data
        employee.user_type = form.user_type.data
        
        db.session.commit()
        flash('Employee details updated successfully!', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('edit_employee.html', form=form, employee=employee)

@app.route('/reset_password/<int:employee_id>', methods=['POST'])
@login_required
def reset_password(employee_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to reset passwords.', 'danger')
        return redirect(url_for('dashboard'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Generate a new temporary password
    characters = string.ascii_letters + string.digits
    temp_password = ''.join(random.choice(characters) for i in range(10))
    employee.password = generate_password_hash(temp_password)
    
    db.session.commit()
    
    # Try to send email
    subject = "Your Password Has Been Reset"
    body = f"""
Dear {employee.full_name},

Your password has been reset by the administrator.

Your new temporary password is: {temp_password}

Please change your password after logging in.

You can access the system at: {request.host_url}

Thank you,
HR Department
"""
    
    email_sent = send_email(employee.email, subject, body)
    
    if email_sent:
        flash('Password reset successfully. Email notification sent.', 'success')
    else:
        # Store the password in session to display to admin
        flash(f'Password reset successfully. New password: {temp_password}. Failed to send email.', 'warning')
    
    return redirect(url_for('manage_employees'))

@app.route('/test_email')
@login_required
def test_email():
    if current_user.user_type != 'admin':
        flash('You do not have permission to test email.', 'danger')
        return redirect(url_for('dashboard'))
    
    test_subject = "HR System Email Test"
    test_body = "This is a test email from your HR system."
    
    if send_email(current_user.email, test_subject, test_body):
        flash('Test email sent successfully!', 'success')
    else:
        flash('Failed to send test email. Please check your email configuration.', 'danger')
    
    return redirect(url_for('dashboard'))

def send_leave_request_notification(leave_request):
    """Send email notification to admins about new leave request"""
    # Get all admin users
    admins = Employee.query.filter(Employee.user_type == 'admin').all()
    
    if not admins:
        return False
    
    subject = f"New Leave Request from {leave_request.employee.full_name}"
    body = f"""
A new leave request has been submitted.

Employee: {leave_request.employee.full_name}
Leave Type: {leave_request.leave_type.title()}
Dates: {leave_request.start_date.strftime('%Y-%m-%d')} to {leave_request.end_date.strftime('%Y-%m-%d')}
Days: {leave_request.days_requested}
Reason: {leave_request.reason}

Please review the request in the HR system.

Thank you,
HR System
"""
    
    # Send email to all admins
    success = True
    for admin in admins:
        if not send_email(admin.email, subject, body):
            success = False
    
    return success

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