import requests
from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_from_directory, Blueprint, send_file, session, jsonify, cli
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import aliased
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date, time
from math import ceil
import io 
import os
import sqlite3
import socket
from http.client import HTTPException
from io import StringIO, BytesIO
import csv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import uuid
import logging
import ipaddress
import pytz
from pytz import timezone
import sys
import werkzeug.serving

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'hr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Define Malaysia timezone
MYT = pytz.timezone('Asia/Kuala_Lumpur')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.after_request
def add_security_headers(response):
    response.headers['Permissions-Policy'] = 'geolocation=()'
    return response

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Output to terminal
        logging.FileHandler('hr_system.log')  # Save to file
    ]
)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'scarletsumirepoh@gmail.com'
app.config['MAIL_PASSWORD'] = 'ipfo egit wyrk uzdb'
app.config['MAIL_DEFAULT_SENDER'] = 'scarletsumirepoh.email@gmail.com'

# Configuration for leave file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'attachments')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Office IP network (adjust to your office's IP range)
app.config['OFFICE_NETWORK'] = '192.168.0.0/16'

def send_email(to_email, subject, body):
    """Send email using SMTP with better error handling"""
    try:
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
- From: {leave_request.start_date.strftime('%d-%m-%y')}
- To: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Status: {status.title()}

Thank you,
HR Department
"""
    return send_email(employee.email, subject, body)

def send_supervisor_notification(leave_request):
    """Send email notification to supervisors about leave requests from their team"""
    supervisors = Employee.query.filter(Employee.user_type == 'supervisor').all()
    
    if not supervisors:
        return False
    
    subject = f"Leave Request from {leave_request.employee.full_name} (Your Team Member)"
    body = f"""
A leave request has been submitted by your team member {leave_request.employee.full_name}.

Details:
- Leave Type: {leave_request.leave_type.title()}
- Start Date: {leave_request.start_date.strftime('%d-%m-%y')}
- End Date: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Please log in to the HR system to review this request if needed.

Thank you,
HR System
"""
    
    success = True
    for supervisor in supervisors:
        if not send_email(supervisor.email, subject, body):
            success = False
    
    return success

# Database Models
class Employee(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nationality = db.Column(db.String(80), nullable=False)
    employee_id = db.Column(db.String(80), unique=True, nullable=False)
    hire_date = db.Column(db.Date)
    is_admin = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='employee')
    last_clock_in = db.Column(db.DateTime)
    last_clock_out = db.Column(db.DateTime)
    last_lunch_start = db.Column(db.DateTime)
    last_lunch_end = db.Column(db.DateTime)
    
    # Use back_populates instead of backref for better control
    leave_balances = db.relationship('LeaveBalance', back_populates='employee', lazy=True)
    
    def generate_temp_password(self):
        """Generate a temporary password"""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(8))

class TimeTracking(db.Model):
    __tablename__ = 'time_tracking'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    action_type = db.Column(db.String(20), nullable=False)  #clock_in, clock_out, lunch_start, lunch_end
    timestamp = db.Column(db.DateTime, nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    address = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), nullable=True)    # in/out office
    ip_address = db.Column(db.String(45), nullable=True)
    employee = db.relationship('Employee', backref=db.backref('time_entries', lazy=True))

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TimeTrackingForm(FlaskForm):
    action_type = StringField('Action Type', validators=[DataRequired()])
    submit = SubmitField('Perform Action')

class AddEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    nationality = StringField('Nationality', validators=[DataRequired()])  # Added nationality
    employee_id = StringField('Employee ID', validators=[DataRequired()])  # Added employee ID
    user_type = SelectField('User Type', choices=[
        ('office', 'Office Employee'),
        ('factory', 'Factory Worker'),
        ('supervisor', 'Supervisor')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Employee')

class BulkAddEmployeesForm(FlaskForm):
    employee_data = TextAreaField('Employee Data', validators=[DataRequired()], 
        description="Format: Full Name,Email,Nationality,Employee ID,User Type (one per line)")
    submit = SubmitField('Add Employees')

class EditEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    nationality = StringField('Nationality', validators=[DataRequired()])  # Added nationality
    employee_id = StringField('Employee ID', validators=[DataRequired()])  # Added employee ID
    user_type = SelectField('User Type', choices=[
        ('office', 'Office Employee'),
        ('factory', 'Factory Worker'),
        ('supervisor', 'Supervisor')
    ], validators=[DataRequired()])
    submit = SubmitField('Update Employee')

class ResetPasswordForm(FlaskForm):
    submit = SubmitField('Reset Password')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.Text)
    attachment_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    days_requested = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    
    # Explicitly specify foreign_keys for both relationships
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref=db.backref('leave_requests', lazy=True))
    approved_by = db.relationship('Employee', foreign_keys=[approved_by_id])

class LeaveRequestForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    leave_type = SelectField('Leave Type', choices=[
        ('annual', 'Annual Leave'),
        ('medical', 'Medical Leave'),
        ('unpaid', 'Unpaid Leave')
    ], validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired()])
    attachment = FileField('Attachment (if needed)', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx'], 
                   'Only images (JPG, PNG), PDF and Word documents are allowed')
    ])
    submit = SubmitField('Confirm')

class LeaveBalance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    leave_type = db.Column(db.String(20), nullable=False)
    total_days = db.Column(db.Integer, default=0)
    used_days = db.Column(db.Integer, default=0)
    remaining_days = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Use back_populates to match the relationship in Employee
    employee = db.relationship('Employee', back_populates='leave_balances')

class LeaveBalanceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    leave_type = db.Column(db.String(20), nullable=False)
    old_total = db.Column(db.Integer, default=0)
    new_total = db.Column(db.Integer, default=0)
    old_used = db.Column(db.Integer, default=0)
    new_used = db.Column(db.Integer, default=0)
    old_remaining = db.Column(db.Integer, default=0)
    new_remaining = db.Column(db.Integer, default=0)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref=db.backref('balance_changes', lazy=True))
    admin = db.relationship('Employee', foreign_keys=[admin_id])

# Database Migration Functions
def add_is_admin_column():
    """Add the is_admin and user_type columns to the employee table if they don't exist"""
    try:
        conn = sqlite3.connect(os.path.join(app.instance_path, 'hr.db'))
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(employee)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_admin' not in columns:
            cursor.execute("ALTER TABLE employee ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
            print("Added is_admin column to employee table")
        
        if 'user_type' not in columns:
            cursor.execute("ALTER TABLE employee ADD COLUMN user_type VARCHAR(20) DEFAULT 'employee'")
            print("Added user_type column to employee table")
        
        # Remove department and position columns if they exist
        if 'department' in columns:
            cursor.execute("ALTER TABLE employee DROP COLUMN department")
            print("Removed department column from employee table")
        
        if 'position' in columns:
            cursor.execute("ALTER TABLE employee DROP COLUMN position")
            print("Removed position column from employee table")
        
        # Add nationality and employee_id columns if they don't exist
        if 'nationality' not in columns:
            cursor.execute("ALTER TABLE employee ADD COLUMN nationality VARCHAR(80)")
            print("Added nationality column to employee table")
        
        if 'employee_id' not in columns:
            cursor.execute("ALTER TABLE employee ADD COLUMN employee_id VARCHAR(80)")
            print("Added employee_id column to employee table")   
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error checking/adding columns: {e}")

def add_time_tracking_columns():
    """Add time tracking columns to the employee table if they don't exist"""
    try:
        conn = sqlite3.connect(os.path.join(app.instance_path, 'hr.db'))
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(employee)")
        columns = [column[1] for column in cursor.fetchall()]
        
        time_tracking_columns = [
            'last_clock_in',
            'last_clock_out',
            'last_lunch_start',
            'last_lunch_end'
        ]
        
        for column in time_tracking_columns:
            if column not in columns:
                cursor.execute(f"ALTER TABLE employee ADD COLUMN {column} DATETIME")
                print(f"Added {column} column to employee table")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='time_tracking'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE time_tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    action_type VARCHAR(20) NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(20),
                    ip_address VARCHAR(45),
                    FOREIGN KEY (employee_id) REFERENCES employee (id)
                )
            """)
            print("Created time_tracking table")
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error checking/adding time tracking columns: {e}")

@app.route('/leave_balance_history')
@login_required
def leave_balance_history():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view leave balance history.', 'danger')
        return redirect(url_for('leaves'))
    
    # Get filter parameters
    employee_id = request.args.get('employee_id', '')
    admin_id = request.args.get('admin_id', '')
    leave_type = request.args.get('leave_type', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Build query
    query = LeaveBalanceHistory.query
    
    if employee_id:
        query = query.filter(LeaveBalanceHistory.employee_id == employee_id)
    if admin_id:
        query = query.filter(LeaveBalanceHistory.admin_id == admin_id)
    if leave_type:
        query = query.filter(LeaveBalanceHistory.leave_type == leave_type)
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%d-%m-%y')
            query = query.filter(LeaveBalanceHistory.created_at >= start_date_obj)
        except ValueError:
            pass
    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%d-%m-%y')
            query = query.filter(LeaveBalanceHistory.created_at <= end_date_obj)
        except ValueError:
            pass
    
    history_records = query.order_by(LeaveBalanceHistory.created_at.desc()).all()
    employees = Employee.query.all()
    admins = Employee.query.filter(Employee.user_type.in_(['admin', 'supervisor'])).all()
    
    return render_template('leave_balance_history.html', 
                         history_records=history_records,
                         employees=employees,
                         admins=admins)

# create initial leave balances
def create_initial_leave_balances():
    employees = Employee.query.all()
    for employee in employees:
        for leave_type in ['annual', 'medical', 'unpaid']:
            # Check if this specific leave type balance exists for the employee
            balance = LeaveBalance.query.filter_by(
                employee_id=employee.id, 
                leave_type=leave_type
            ).first()
            
            if not balance:
                default_days = 20 if leave_type == 'annual' else (14 if leave_type == 'medical' else 0)
                balance = LeaveBalance(
                    employee_id=employee.id,
                    leave_type=leave_type,
                    total_days=default_days,
                    used_days=0,
                    remaining_days=default_days
                )
                db.session.add(balance)
    db.session.commit()

def add_leave_balance_tables():
    """Add leave balance and history tables if they don't exist"""
    try:
        conn = sqlite3.connect(os.path.join(app.instance_path, 'hr.db'))
        cursor = conn.cursor()
        
        # Check if leave_balance table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leave_balance'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE leave_balance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    leave_type VARCHAR(20) NOT NULL,
                    total_days INTEGER DEFAULT 0,
                    used_days INTEGER DEFAULT 0,
                    remaining_days INTEGER DEFAULT 0,
                    updated_at DATETIME,
                    FOREIGN KEY (employee_id) REFERENCES employee (id)
                )
            """)
            print("Created leave_balance table")
        
        # Check if leave_balance_history table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leave_balance_history'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE leave_balance_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    admin_id INTEGER NOT NULL,
                    leave_type VARCHAR(20) NOT NULL,
                    old_total INTEGER DEFAULT 0,
                    new_total INTEGER DEFAULT 0,
                    old_used INTEGER DEFAULT 0,
                    new_used INTEGER DEFAULT 0,
                    old_remaining INTEGER DEFAULT 0,
                    new_remaining INTEGER DEFAULT 0,
                    comment TEXT,
                    created_at DATETIME,
                    FOREIGN KEY (employee_id) REFERENCES employee (id),
                    FOREIGN KEY (admin_id) REFERENCES employee (id)
                )
            """)
            print("Created leave_balance_history table")
        
        conn.commit()
        conn.close()
        
        # Create initial leave balances
        create_initial_leave_balances()
        
    except Exception as e:
        print(f"Error creating leave balance tables: {e}")

# Routes and Logic
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Employee, int(user_id))

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

with app.app_context():
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    db.create_all()
    print("Database tables created!")
    add_is_admin_column()
    add_time_tracking_columns()
    add_leave_balance_tables()

@app.before_request
def before_request():
    if request.url.startswith('https://'):
        new_url = request.url.replace('https://', 'http://', 1)
        return redirect(new_url, code=301)

original_handle = werkzeug.serving.WSGIRequestHandler.handle

def handle_corrupted_headers(self):
    try:
        return original_handle(self)
    except (UnicodeDecodeError, ValueError, HTTPException) as e:
        if "Bad request version" in str(e) or "Bad HTTP/0.9 request type" in str(e):
            print(f"Intercepted malformed HTTPS request, redirecting to HTTP...")
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
        raise

werkzeug.serving.WSGIRequestHandler.handle = handle_corrupted_headers

def validate_leave_days(leave_type, days_requested):
    """Validate leave days based on leave type"""
    max_days = {
        'annual': 365,
        'medical': 60,
        'unpaid': 365  # Unlimited but set a reasonable max
    }
    
    if leave_type not in max_days:
        return False, "Invalid leave type"
    
    max_allowed = max_days[leave_type]
    
    if days_requested > max_allowed:
        return False, f"{leave_type.title()} leave is limited to {max_allowed} days"
    
    return True, ""

def send_leave_request_notification(leave_request):
    """Send email notification to admins about new leave request"""
    admins = Employee.query.filter(Employee.user_type == 'admin').all()
    
    if not admins:
        return False
    
    subject = f"New Leave Request from {leave_request.employee.full_name}"
    body = f"""
A new leave request has been submitted.

Employee: {leave_request.employee.full_name}
Leave Type: {leave_request.leave_type.title()}
Dates: {leave_request.start_date.strftime('%d-%m-%y')} to {leave_request.end_date.strftime('%d-%m-%y')}
Days: {leave_request.days_requested}
Reason: {leave_request.reason}

Please review the request in the HR system.

Thank you,
Hercules HR
"""
    
    success = True
    for admin in admins:
        if not send_email(admin.email, subject, body):
            success = False
    
    return success

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/create_test_users')
def create_test_users():
    if not Employee.query.filter_by(username='admin').first():
        admin_user = Employee(
            username='admin',
            password=generate_password_hash('temp_password'),
            full_name='Admin User',
            email='scarletsumirepoh@gmail.com',
            nationality='Malaysian',  # Added nationality
            employee_id='ADM001',     # Added employee ID
            hire_date=datetime.utcnow(),
            is_admin=True,
            user_type='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")
    
    if not Employee.query.filter_by(username='samchong').first():
        samuel_user = Employee(
            username='samchong',
            password=generate_password_hash('password123'),
            full_name='Samuel Chong',
            email='samuel.chong@example.com',
            nationality='Malaysian',  # Added nationality
            employee_id='EMP001',     # Added employee ID
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='office'
        )
        db.session.add(samuel_user)
        db.session.commit()
        print("Samuel Chong user created")
    
    if not Employee.query.filter_by(username='factory1').first():
        factory_user = Employee(
            username='factory1',
            password=generate_password_hash('factory123'),
            full_name='Factory Worker',
            email='factory@example.com',
            nationality='Malaysian',  # Added nationality
            employee_id='FAC001',     # Added employee ID
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='factory'
        )
        db.session.add(factory_user)
        db.session.commit()
        print("Factory user created")
    
    if not Employee.query.filter_by(username='supervisor1').first():
        supervisor_user = Employee(
            username='supervisor1',
            password=generate_password_hash('super123'),
            full_name='Supervisor User',
            email='supervisor@example.com',
            nationality='Malaysian',  # Added nationality
            employee_id='SUP001',     # Added employee ID
            hire_date=datetime.utcnow(),
            is_admin=False,
            user_type='supervisor'
        )
        db.session.add(supervisor_user)
        db.session.commit()
        print("Supervisor user created")
    
    # Create initial leave balances for all employees
    create_initial_leave_balances()
    
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
    form = TimeTrackingForm()
    now = datetime.now(MYT)  # Set current time to MYT
    
    # Get latest clock-in and lunch records for the current day
    latest_clock_in = TimeTracking.query.filter(
        TimeTracking.employee_id == current_user.id,
        TimeTracking.action_type == 'clock_in',
        func.date(TimeTracking.timestamp) == now.date()
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    latest_lunch_start = TimeTracking.query.filter(
        TimeTracking.employee_id == current_user.id,
        TimeTracking.action_type == 'lunch_start',
        func.date(TimeTracking.timestamp) == now.date()
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    latest_lunch_end = TimeTracking.query.filter(
        TimeTracking.employee_id == current_user.id,
        TimeTracking.action_type == 'lunch_end',
        func.date(TimeTracking.timestamp) == now.date()
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    latest_clock_out = TimeTracking.query.filter(
        TimeTracking.employee_id == current_user.id,
        TimeTracking.action_type == 'clock_out',
        func.date(TimeTracking.timestamp) == now.date()
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    # Get leave statistics for the dashboard
    remaining_leave = 0
    pending_requests = 0
    approved_leaves = 0
    
    # Get remaining annual leave days
    annual_balance = LeaveBalance.query.filter_by(
        employee_id=current_user.id,
        leave_type='annual'
    ).first()
    
    if annual_balance:
        remaining_leave = annual_balance.remaining_days
    
    # Get pending leave requests count
    pending_requests = LeaveRequest.query.filter_by(
        employee_id=current_user.id,
        status='pending'
    ).count()
    
    # Get approved leave requests count (this year)
    current_year = datetime.now().year
    approved_leaves = LeaveRequest.query.filter(
        LeaveRequest.employee_id == current_user.id,
        LeaveRequest.status == 'approved',
        db.extract('year', LeaveRequest.start_date) == current_year
    ).count()
    
    if current_user.user_type == 'factory':
        return render_template(
            'factory_dashboard.html',
            form=form,
            now=now,
            MYT=MYT,
            latest_clock_in=latest_clock_in,
            latest_clock_out=latest_clock_out,
            latest_lunch_start=latest_lunch_start,
            latest_lunch_end=latest_lunch_end,
            remaining_leave=remaining_leave,
            pending_requests=pending_requests,
            approved_leaves=approved_leaves
        )
    
    return render_template(
        'dashboard.html',
        form=form,
        now=now,
        MYT=MYT,
        latest_clock_in=latest_clock_in,
        latest_clock_out=latest_clock_out,
        latest_lunch_start=latest_lunch_start,
        latest_lunch_end=latest_lunch_end,
        remaining_leave=remaining_leave,
        pending_requests=pending_requests,
        approved_leaves=approved_leaves
    )

@app.route('/log_error', methods=['POST'])
def log_error():
    error_data = request.get_json()
    logging.error(f"Client-side error: {error_data}")
    return '', 204

@app.route('/time_tracking', methods=['POST'])
@login_required
def time_tracking():
    form = TimeTrackingForm()
    if form.validate_on_submit():
        action_type = request.form.get('action_type')
        now = datetime.now(MYT)  # Use MYT timezone
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        address = request.form.get('address')
        ip_address = request.remote_addr

        # Determine status based on IP address
        status = 'in_office' if is_ip_in_office_network(ip_address) else 'out_of_office'

        # Validate state for clock_out and lunch actions
        latest_clock_in = TimeTracking.query.filter(
            TimeTracking.employee_id == current_user.id,
            TimeTracking.action_type == 'clock_in',
            func.date(TimeTracking.timestamp) == now.date()
        ).order_by(TimeTracking.timestamp.desc()).first()
        
        latest_clock_out = TimeTracking.query.filter(
            TimeTracking.employee_id == current_user.id,
            TimeTracking.action_type == 'clock_out',
            func.date(TimeTracking.timestamp) == now.date()
        ).order_by(TimeTracking.timestamp.desc()).first()
        
        latest_lunch_start = TimeTracking.query.filter(
            TimeTracking.employee_id == current_user.id,
            TimeTracking.action_type == 'lunch_start',
            func.date(TimeTracking.timestamp) == now.date()
        ).order_by(TimeTracking.timestamp.desc()).first()
        
        latest_lunch_end = TimeTracking.query.filter(
            TimeTracking.employee_id == current_user.id,
            TimeTracking.action_type == 'lunch_end',
            func.date(TimeTracking.timestamp) == now.date()
        ).order_by(TimeTracking.timestamp.desc()).first()

        # VALIDATION: Prevent multiple clock-outs in the same day
        if action_type == 'clock_out':
            if not latest_clock_in:
                db.session.rollback()
                flash('No clock-in record found for today.', 'danger')
                return redirect(url_for('dashboard'))
            if latest_clock_out:
                db.session.rollback()
                flash('You have already clocked out today.', 'danger')
                return redirect(url_for('dashboard'))
            # Automatically end lunch if lunch_start exists without lunch_end
            if latest_lunch_start and not latest_lunch_end:
                lunch_end_entry = TimeTracking(
                    employee_id=current_user.id,
                    action_type='lunch_end',
                    timestamp=now,
                    latitude=latitude if latitude else None,
                    longitude=longitude if longitude else None,
                    address=address if address else 'Unknown',
                    ip_address=ip_address,
                    status=status
                )
                db.session.add(lunch_end_entry)
                
        elif action_type == 'clock_in':
            if latest_clock_in and latest_clock_in.timestamp.date() == now.date():
                db.session.rollback()
                flash('You have already clocked in today.', 'danger')
                return redirect(url_for('dashboard'))
                
        elif action_type == 'lunch_start':
            if not latest_clock_in:
                db.session.rollback()
                flash('Cannot start lunch: No clock-in found for today.', 'danger')
                return redirect(url_for('dashboard'))
            if latest_lunch_start and not latest_lunch_end:
                db.session.rollback()
                flash('Cannot start lunch: Lunch already started.', 'danger')
                return redirect(url_for('dashboard'))
            if latest_lunch_start and latest_lunch_end:
                db.session.rollback()
                flash('Cannot start lunch: Lunch already completed for today.', 'danger')
                return redirect(url_for('dashboard'))
                
        elif action_type == 'lunch_end':
            if not latest_lunch_start:
                db.session.rollback()
                flash('No lunch start record found for today.', 'danger')
                return redirect(url_for('dashboard'))
            if latest_lunch_end:
                db.session.rollback()
                flash('You have already ended lunch today.', 'danger')
                return redirect(url_for('dashboard'))

        # Create a new time tracking entry
        time_entry = TimeTracking(
            employee_id=current_user.id,
            action_type=action_type,
            timestamp=now,
            latitude=latitude if latitude else None,
            longitude=longitude if longitude else None,
            address=address if address else 'Unknown',
            ip_address=ip_address,
            status=status
        )
        db.session.add(time_entry)

        try:
            db.session.commit()
            
            # Update employee's last action timestamps
            employee = Employee.query.get(current_user.id)
            if action_type == 'clock_in':
                employee.last_clock_in = now
            elif action_type == 'clock_out':
                employee.last_clock_out = now
            elif action_type == 'lunch_start':
                employee.last_lunch_start = now
            elif action_type == 'lunch_end':
                employee.last_lunch_end = now
            
            db.session.commit()
            
            flash(f'Successfully {action_type.replace("_", " ")}!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error during {action_type.replace("_", " ")}: {str(e)}', 'danger')
    else:
        flash('Invalid form submission.', 'danger')
    return redirect(url_for('dashboard'))

def can_perform_time_action(employee, action_type):
    """Check if employee can perform the requested time action"""
    now = datetime.utcnow()
    today = now.date()
    
    if action_type == 'clock_in':
        if employee.last_clock_in and employee.last_clock_in.date() == today:
            return False, 'You have already clocked in today.'
        return True, ''
    
    elif action_type == 'clock_out':
        if not employee.last_clock_in or employee.last_clock_in.date() != today:
            return False, 'You must clock in first.'
        if employee.last_clock_out and employee.last_clock_out.date() == today:
            return False, 'You have already clocked out today.'
        return True, ''
    
    elif action_type == 'lunch_start':
        if not employee.last_clock_in or employee.last_clock_in.date() != today:
            return False, 'You must clock in first.'
        if employee.last_lunch_start and employee.last_lunch_start.date() == today:
            return False, 'You have already started lunch today.'
        return True, ''
    
    elif action_type == 'lunch_end':
        if not employee.last_lunch_start or employee.last_lunch_start.date() != today:
            return False, 'You must start lunch first.'
        if employee.last_lunch_end and employee.last_lunch_end.date() == today:
            return False, 'You have already ended lunch today.'
        return True, ''
    
    return False, 'Invalid action.'

def is_ip_in_office_network(ip_address):
    """Check if the IP address is within the office network range."""
    try:
        ip = ipaddress.ip_address(ip_address)
        office_network = ipaddress.ip_network(app.config['OFFICE_NETWORK'], strict=False)
        return ip in office_network
    except ValueError:
        return False

@app.route('/department_directory')
@login_required
def department_directory():
    employees = Employee.query.all()
    
    # Group employees by user_type
    employees_by_type = {
        'supervisor': [],
        'office': [],
        'factory': []
    }
    
    for employee in employees:
        if employee.user_type in employees_by_type:
            employees_by_type[employee.user_type].append(employee)
    
    return render_template('department_directory.html', 
                         employees_by_type=employees_by_type)

@app.route('/performance_reviews')
@login_required
def performance_reviews():
    return render_template('performance_reviews.html')

@app.route('/leaves')
@login_required
def leaves():
    if current_user.user_type in ['admin', 'supervisor']:
        # Show pending requests for approval AND the user's own requests
        pending_requests = LeaveRequest.query.filter_by(status='pending').all()
        user_requests = LeaveRequest.query.filter_by(employee_id=current_user.id).order_by(LeaveRequest.created_at.desc()).all()
        return render_template('leaves.html', 
                             pending_requests=pending_requests, 
                             user_requests=user_requests,
                             is_admin_view=True)
    else:
        # Regular employees only see their own requests
        user_requests = LeaveRequest.query.filter_by(employee_id=current_user.id).order_by(LeaveRequest.created_at.desc()).all()
        return render_template('leaves.html', 
                             user_requests=user_requests,
                             is_admin_view=False)

@app.route('/request_leave', methods=['GET', 'POST'])
@login_required
def request_leave():
    form = LeaveRequestForm()
    
    if form.validate_on_submit():
        delta = form.end_date.data - form.start_date.data
        days_requested = delta.days + 1
        
        # Check if end date is before start date
        if form.end_date.data < form.start_date.data:
            flash('End date cannot be before start date.', 'danger')
            return render_template('request_leave.html', form=form)
        
        # Check for overlapping leave requests (approved or pending)
        overlapping_leaves = LeaveRequest.query.filter(
            LeaveRequest.employee_id == current_user.id,
            LeaveRequest.status.in_(['approved', 'pending']),
            LeaveRequest.id != (request.args.get('request_id') if request.args.get('request_id') else None),  # Exclude current request when editing
            db.or_(
                # New leave starts during existing leave
                db.and_(
                    form.start_date.data >= LeaveRequest.start_date,
                    form.start_date.data <= LeaveRequest.end_date
                ),
                # New leave ends during existing leave
                db.and_(
                    form.end_date.data >= LeaveRequest.start_date,
                    form.end_date.data <= LeaveRequest.end_date
                ),
                # New leave completely contains existing leave
                db.and_(
                    form.start_date.data <= LeaveRequest.start_date,
                    form.end_date.data >= LeaveRequest.end_date
                )
            )
        ).all()
        
        if overlapping_leaves:
            overlap_messages = []
            for overlap in overlapping_leaves:
                status_display = overlap.status.title()
                overlap_messages.append(
                    f"{status_display} leave from {overlap.start_date.strftime('%d-%m-%y')} to "
                    f"{overlap.end_date.strftime('%d-%m-%y')} ({overlap.leave_type.title()})"
                    f"{': ' + overlap.reason if overlap.reason else ''}"
                )
            
            flash('Your leave request overlaps with existing leave(s): ' + ', '.join(overlap_messages), 'danger')
            return render_template('request_leave.html', form=form)
      
        is_valid, error_message = validate_leave_days(form.leave_type.data, days_requested)
        
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('request_leave.html', form=form)
        
        # Check if user has sufficient leave balance for paid leave types
        if form.leave_type.data in ['annual', 'medical']:
            leave_balance = LeaveBalance.query.filter_by(
                employee_id=current_user.id,
                leave_type=form.leave_type.data
            ).first()
            
            if not leave_balance:
                # If no balance record exists, create one with default values
                default_days = 20 if form.leave_type.data == 'annual' else 14
                leave_balance = LeaveBalance(
                    employee_id=current_user.id,
                    leave_type=form.leave_type.data,
                    total_days=default_days,
                    used_days=0,
                    remaining_days=default_days
                )
                db.session.add(leave_balance)
                db.session.commit()
                flash(f'Created new {form.leave_type.data} leave balance with {default_days} days.', 'info')
            
            if leave_balance.remaining_days < days_requested:
                flash(f'Insufficient {form.leave_type.data} leave balance. You have {leave_balance.remaining_days} days remaining, but requested {days_requested} days.', 'danger')
                return render_template('request_leave.html', form=form)
        
        attachment_filename = None
        if form.attachment.data:
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            filename = secure_filename(form.attachment.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            form.attachment.data.save(file_path)
            attachment_filename = unique_filename
        
        leave_request = LeaveRequest(
            employee_id=current_user.id,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            leave_type=form.leave_type.data,
            reason=form.reason.data,
            attachment_filename=attachment_filename,
            status='pending',
            days_requested=days_requested
        )
        
        db.session.add(leave_request)
        db.session.commit()
        
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
    
    # Prevent users from approving their own leave requests
    if leave_request.employee_id == current_user.id:
        flash('You cannot approve your own leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request.status = 'approved'
    leave_request.approved_at = datetime.utcnow()
    leave_request.approved_by_id = current_user.id
    
    # Deduct leave balance only for paid leave types
    if leave_request.leave_type in ['annual', 'medical']:
        leave_balance = LeaveBalance.query.filter_by(
            employee_id=leave_request.employee_id,
            leave_type=leave_request.leave_type
        ).first()
        
        if leave_balance:
            if leave_balance.remaining_days >= leave_request.days_requested:
                # Store old values
                old_remaining = leave_balance.remaining_days
                old_used = leave_balance.used_days
                
                # Update balance
                leave_balance.used_days += leave_request.days_requested
                leave_balance.remaining_days -= leave_request.days_requested
                
                # Create leave balance history record
                history = LeaveBalanceHistory(
                    employee_id=leave_request.employee_id,
                    admin_id=current_user.id,
                    leave_type=leave_request.leave_type,
                    old_total=leave_balance.total_days,
                    new_total=leave_balance.total_days,
                    old_used=old_used,
                    new_used=leave_balance.used_days,
                    old_remaining=old_remaining,
                    new_remaining=leave_balance.remaining_days,
                    comment=f"Leave request approved: {leave_request.reason}"
                )
                db.session.add(history)
            else:
                flash(f'Insufficient {leave_request.leave_type} leave balance. Approval granted but balance not deducted.', 'warning')
        else:
            flash(f'No {leave_request.leave_type} leave balance found for employee. Approval granted but balance not deducted.', 'warning')
    
    db.session.commit()
    
    subject = f"Your Leave Request Has Been Approved"
    body = f"""
Dear {leave_request.employee.full_name},

Your leave request has been approved by {current_user.full_name}.

Details:
- Leave Type: {leave_request.leave_type.title()}
- Start Date: {leave_request.start_date.strftime('%d-%m-%y')}
- End Date: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Status: Approved

Thank you,
HR Department
"""
    if send_email(leave_request.employee.email, subject, body):
        flash('Leave request approved successfully. Email notification sent to employee.', 'success')
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
    
    # Prevent users from rejecting their own leave requests
    if leave_request.employee_id == current_user.id:
        flash('You cannot reject your own leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request.status = 'rejected'
    leave_request.approved_at = datetime.utcnow()
    leave_request.approved_by_id = current_user.id
    
    db.session.commit()
    
    subject = f"Your Leave Request Has Been Rejected"
    body = f"""
Dear {leave_request.employee.full_name},

Your leave request has been rejected by {current_user.full_name}.

Details:
- Leave Type: {leave_request.leave_type.title()}
- Start Date: {leave_request.start_date.strftime('%d-%m-%y')}
- End Date: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Status: Rejected

If you have any questions, please contact HR.

Thank you,
HR Department
"""
    if send_email(leave_request.employee.email, subject, body):
        flash('Leave request rejected successfully. Email notification sent to employee.', 'success')
    else:
        flash('Leave request rejected successfully, but failed to send email notification.', 'warning')
    
    return redirect(url_for('leaves'))

@app.route('/manage_employees')
@login_required
def manage_employees():
    if current_user.user_type != 'admin':
        flash('You do not have permission to manage employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get search query from URL parameters
    search_query = request.args.get('search', '').strip()
    
    # Start with base query (exclude admin users)
    query = Employee.query.filter(Employee.user_type != 'admin')
    
    # Apply search filter if search query is provided
    if search_query:
        # Search by name (partial match) OR employee_id (exact match)
        query = query.filter(
            db.or_(
                Employee.full_name.ilike(f'%{search_query}%'),  # Partial name match
                Employee.employee_id.ilike(f'%{search_query}%')  # Partial employee ID match
            )
        )
    
    # Order by employee name
    employees = query.order_by(Employee.full_name).all()
    
    return render_template('manage_employees.html', 
                         employees=employees, 
                         search_query=search_query)

@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.user_type != 'admin':
        flash('You do not have permission to add employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = AddEmployeeForm()
    
    if form.validate_on_submit():
        username = form.email.data.split('@')[0]
        
        # Check for duplicate username
        if Employee.query.filter_by(username=username).first():
            flash('Username already exists. Please use a different email.', 'danger')
            return render_template('add_employee.html', form=form)
        
        # Check for duplicate employee ID
        if Employee.query.filter_by(employee_id=form.employee_id.data).first():
            flash('Employee ID already exists. Please use a different ID.', 'danger')
            return render_template('add_employee.html', form=form)
        
        # Check for duplicate email (added this check)
        if Employee.query.filter_by(email=form.email.data).first():
            flash('Email address already exists. Please use a different email.', 'danger')
            return render_template('add_employee.html', form=form)
        
        # Capitalize nationality: first letter uppercase, rest lowercase
        nationality = form.nationality.data.strip().title()
        
        temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
        
        employee = Employee(
            username=username,
            password=generate_password_hash(temp_password),
            full_name=form.full_name.data,
            email=form.email.data,
            nationality=nationality,  # Use the capitalized version
            employee_id=form.employee_id.data,
            user_type=form.user_type.data,
            hire_date=datetime.utcnow().date()
        )
        
        db.session.add(employee)
        db.session.commit()
        
        # Create leave balances for the new employee - ADD THIS AFTER COMMIT
        for leave_type in ['annual', 'medical', 'unpaid']:
            default_days = 20 if leave_type == 'annual' else (14 if leave_type == 'medical' else 0)
            balance = LeaveBalance(
                employee_id=employee.id,
                leave_type=leave_type,
                total_days=default_days,
                used_days=0,
                remaining_days=default_days
            )
            db.session.add(balance)
        
        db.session.commit()
        
        # Get the current server URL dynamically
        server_url = request.host_url.rstrip('/')
        
        subject = "Your Hercules HR Account Has Been Created"
        body = f"""
Dear {form.full_name.data},

We’re excited to welcome you to Hercules HR! 🎉  
Your account has been successfully created, you can now access the system to manage your profile and explore its features.

Here are your login details:
Username: {username}
Temporary Password: {temp_password}

👉 Please make sure to change your password after your first login for security purposes.  

You can log in here: {server_url}

If you have any questions or need assistance, feel free to reach out to the HR team.  

Welcome aboard,  
Hercules HR Dev
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
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to add employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = BulkAddEmployeesForm()
    
    if form.validate_on_submit():
        lines = form.employee_data.data.strip().split('\n')
        success_count = 0
        error_count = 0
        employees_added = []  # Store successfully added employees
        
        for line in lines:
            try:
                data = [item.strip() for item in line.split(',')]
                if len(data) != 5:
                    error_count += 1
                    continue
                
                full_name, email, nationality, employee_id, user_type = data
                
                # Capitalize nationality: first letter uppercase, rest lowercase
                nationality = nationality.title()
                
                username = email.split('@')[0]
                
                if Employee.query.filter((Employee.username == username) | (Employee.email == email) | (Employee.employee_id == employee_id)).first():
                    error_count += 1
                    continue
                
                temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                
                employee = Employee(
                    username=username,
                    password=generate_password_hash(temp_password),
                    full_name=full_name,
                    email=email,
                    nationality=nationality,  # Use the capitalized version
                    employee_id=employee_id,
                    user_type=user_type,
                    hire_date=datetime.utcnow().date()
                )
                
                db.session.add(employee)
                employees_added.append(employee)  # Add to list for leave balance creation
                success_count += 1
                
                # Get the current server URL dynamically
                server_url = request.host_url.rstrip('/')
                
                subject = "Your Hercules HR Account Has Been Created"
                body = f"""
Dear {full_name},  <!-- CHANGED: Use full_name variable instead of form.full_name.data -->

We're excited to welcome you to Hercules HR! 🎉  
Your account has been successfully created, you can now access the system to manage your profile and explore its features.

Here are your login details:
Username: {username}
Temporary Password: {temp_password}

👉 Please make sure to change your password after your first login for security purposes.  

You can log in here: {server_url}

If you have any questions or need assistance, feel free to reach out to the HR team.  

Welcome aboard,  
Hercules HR Dev
"""
                send_email(email, subject, body)
                
            except Exception as e:
                print(f"Error adding employee: {e}")
                error_count += 1
        
        db.session.commit()
        
        # Create leave balances for all successfully added employees
        for employee in employees_added:
            for leave_type in ['annual', 'medical', 'unpaid']:
                default_days = 20 if leave_type == 'annual' else (14 if leave_type == 'medical' else 0)
                balance = LeaveBalance(
                    employee_id=employee.id,
                    leave_type=leave_type,
                    total_days=default_days,
                    used_days=0,
                    remaining_days=default_days
                )
                db.session.add(balance)
        
        db.session.commit()
        
        flash(f'Added {success_count} employees successfully. {error_count} failed.', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('bulk_add_employees.html', form=form)

@app.route('/delete_employee/<int:employee_id>', methods=['POST'])
@login_required
def delete_employee(employee_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to delete employees.', 'danger')
        return redirect(url_for('manage_employees'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Prevent deletion of the current user
    if employee.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_employees'))
    
    # Delete related records first (leave requests, time tracking, leave balances)
    LeaveRequest.query.filter_by(employee_id=employee_id).delete()
    TimeTracking.query.filter_by(employee_id=employee_id).delete()
    LeaveBalance.query.filter_by(employee_id=employee_id).delete()  # Add this line
    
    # Delete the employee
    db.session.delete(employee)
    db.session.commit()
    
    flash(f'Employee {employee.full_name} has been deleted successfully.', 'success')
    return redirect(url_for('manage_employees'))

@app.route('/download_attachment/<filename>', endpoint='download_attachment')
@login_required
def download_leave_attachment(filename):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view attachments.', 'danger')
        return redirect(url_for('leaves'))
    
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
        # Check if employee ID is already taken by another employee
        if form.employee_id.data != employee.employee_id and Employee.query.filter_by(employee_id=form.employee_id.data).first():
            flash('Employee ID already exists. Please use a different ID.', 'danger')
            return render_template('edit_employee.html', form=form, employee=employee)
        
        # Capitalize nationality: first letter uppercase, rest lowercase
        nationality = form.nationality.data.strip().title()
        
        employee.full_name = form.full_name.data
        employee.email = form.email.data
        employee.nationality = nationality  # Use the capitalized version
        employee.employee_id = form.employee_id.data
        employee.user_type = form.user_type.data
        
        db.session.commit()
        
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('edit_employee.html', form=form, employee=employee)

@app.route('/edit_attendance/<int:employee_id>/<string:date_str>', methods=['GET', 'POST'])
@login_required
def edit_attendance(employee_id, date_str):
    # Check permission
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to edit attendance.', 'danger')
        return redirect(url_for('reports'))
    
    # Convert date string to date object
    try:
        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('reports'))
    
    # Get employee and check supervisor permission
    employee = Employee.query.get_or_404(employee_id)
    
    if current_user.user_type == 'supervisor' and employee.supervisor_id != current_user.id:
        flash('You can only edit attendance for your team members.', 'danger')
        return redirect(url_for('reports'))
    
    # Get all time records for this employee on this date
    start_datetime = datetime.combine(target_date, time.min)
    end_datetime = datetime.combine(target_date, time.max)
    
    time_records = TimeTracking.query.filter(
        TimeTracking.employee_id == employee_id,
        TimeTracking.timestamp >= start_datetime,
        TimeTracking.timestamp <= end_datetime
    ).order_by(TimeTracking.timestamp).all()
    
    if request.method == 'POST':
        # Handle form submission
        clock_in_time = request.form.get('clock_in')
        clock_out_time = request.form.get('clock_out')
        action = request.form.get('action')
        
        # Delete existing records if requested
        if action == 'delete':
            for record in time_records:
                db.session.delete(record)
            db.session.commit()
            flash('Attendance records deleted successfully.', 'success')
            return redirect(url_for('reports'))
        
        # Update or create records
        if clock_in_time:
            clock_in_datetime = datetime.combine(target_date, datetime.strptime(clock_in_time, '%H:%M').time())
            # Find or create clock-in record
            clock_in_record = next((r for r in time_records if r.action_type == 'clock_in'), None)
            if clock_in_record:
                clock_in_record.timestamp = clock_in_datetime
            else:
                clock_in_record = TimeTracking(
                    employee_id=employee_id,
                    action_type='clock_in',
                    timestamp=clock_in_datetime
                )
                db.session.add(clock_in_record)
        
        if clock_out_time:
            clock_out_datetime = datetime.combine(target_date, datetime.strptime(clock_out_time, '%H:%M').time())
            # Find or create clock-out record
            clock_out_record = next((r for r in time_records if r.action_type == 'clock_out'), None)
            if clock_out_record:
                clock_out_record.timestamp = clock_out_datetime
            else:
                clock_out_record = TimeTracking(
                    employee_id=employee_id,
                    action_type='clock_out',
                    timestamp=clock_out_datetime
                )
                db.session.add(clock_out_record)
        
        db.session.commit()
        flash('Attendance updated successfully.', 'success')
        return redirect(url_for('reports'))
    
    # Pre-fill form with existing data
    clock_in = None
    clock_out = None
    
    for record in time_records:
        if record.action_type == 'clock_in':
            clock_in = record.timestamp.time().strftime('%H:%M')
        elif record.action_type == 'clock_out':
            clock_out = record.timestamp.time().strftime('%H:%M')
    
    return render_template('edit_attendance.html',
                         employee=employee,
                         date=target_date,
                         clock_in=clock_in,
                         clock_out=clock_out,
                         time_records=time_records)

@app.route('/all_leaves')
@login_required
def all_leaves():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view all leaves.', 'danger')
        return redirect(url_for('leaves'))

    employee_id = request.args.get('employee_id', '')
    leave_type = request.args.get('leave_type', '')
    status = request.args.get('status', '')
    start_date_filter = request.args.get('start_date_filter', '')
    end_date_filter = request.args.get('end_date_filter', '')
    days_requested = request.args.get('days_requested', '')
    reason = request.args.get('reason', '')
    
    # Create alias for the approver
    Approver = db.aliased(Employee)
    
    # Start with base query joining employee and approver
    query = db.session.query(
        LeaveRequest, 
        Employee.full_name.label('employee_name'),
        db.func.coalesce(Approver.full_name, 'N/A').label('approver_name')
    ).join(
        Employee, LeaveRequest.employee_id == Employee.id
    ).outerjoin(
        Approver, LeaveRequest.approved_by_id == Approver.id
    )
    
    if employee_id:
        query = query.filter(LeaveRequest.employee_id == employee_id)
    
    if leave_type:
        query = query.filter(LeaveRequest.leave_type == leave_type)
    
    if status:
        query = query.filter(LeaveRequest.status == status)
    
    if start_date_filter:
        try:
            start_date = datetime.strptime(start_date_filter, '%d-%m-%y').date()
            query = query.filter(LeaveRequest.start_date >= start_date)
        except ValueError:
            pass
    
    if end_date_filter:
        try:
            end_date = datetime.strptime(end_date_filter, '%d-%m-%y').date()
            query = query.filter(LeaveRequest.start_date <= end_date)
        except ValueError:
            pass
    
    if days_requested:
        try:
            query = query.filter(LeaveRequest.days_requested == int(days_requested))
        except ValueError:
            pass
    
    if reason:
        query = query.filter(LeaveRequest.reason.ilike(f'%%{reason}%%'))
    
    # Execute query and format results
    results = query.order_by(LeaveRequest.created_at.desc()).all()
    
    # Format the data for template
    all_requests = []
    for result in results:
        leave_request, employee_name, approver_name = result
        all_requests.append({
            'leave_request': leave_request,
            'employee_name': employee_name,
            'approver_name': approver_name
        })
    
    employees = Employee.query.all()
    
    return render_template('all_leaves.html', 
                         all_requests=all_requests, 
                         employees=employees,
                         filters=request.args)

@app.route('/export_leaves')
@login_required
def export_leaves():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to export leaves.', 'danger')
        return redirect(url_for('leaves'))
    
    employee_id = request.args.get('employee_id', '')
    leave_type = request.args.get('leave_type', '')
    status = request.args.get('status', '')
    start_date_filter = request.args.get('start_date_filter', '')
    end_date_filter = request.args.get('end_date_filter', '')
    days_requested = request.args.get('days_requested', '')
    reason = request.args.get('reason', '')
    
    # Corrected query - use aliased Employee for approver
    ApproverAlias = db.aliased(Employee, name='approver')
    
    query = db.session.query(
        LeaveRequest, 
        Employee.full_name.label('employee_name'),
        db.func.coalesce(ApproverAlias.full_name, 'N/A').label('approver_name')
    ).join(
        Employee, LeaveRequest.employee_id == Employee.id
    ).outerjoin(
        ApproverAlias, LeaveRequest.approved_by_id == ApproverAlias.id
    )
    
    if employee_id:
        query = query.filter(LeaveRequest.employee_id == employee_id)
    
    if leave_type:
        query = query.filter(LeaveRequest.leave_type == leave_type)
    
    if status:
        query = query.filter(LeaveRequest.status == status)
    
    if start_date_filter:
        try:
            start_date = datetime.strptime(start_date_filter, '%d-%m-%y').date()
            query = query.filter(LeaveRequest.start_date >= start_date)
        except ValueError:
            pass
    
    if end_date_filter:
        try:
            end_date = datetime.strptime(end_date_filter, '%d-%m-%y').date()
            query = query.filter(LeaveRequest.start_date <= end_date)
        except ValueError:
            pass
    
    if days_requested:
        try:
            query = query.filter(LeaveRequest.days_requested == int(days_requested))
        except ValueError:
            pass
    
    if reason:
        query = query.filter(LeaveRequest.reason.ilike(f'%%{reason}%%'))
    
    # Execute query
    results = query.order_by(LeaveRequest.created_at.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header row with new column
    writer.writerow(['Employee Name', 'Leave Type', 'Start Date', 'End Date', 
                     'Days Requested', 'Status', 'Reason', 'Approved/Rejected By', 
                     'Submitted On', 'Approved/Rejected On'])
    
    # Write data rows
    for result in results:
        leave_request, employee_name, approver_name = result
        
        writer.writerow([
            employee_name,
            leave_request.leave_type.title(),
            leave_request.start_date.strftime('%d-%m-%y'),
            leave_request.end_date.strftime('%d-%m-%y'),
            leave_request.days_requested,
            leave_request.status.title(),
            leave_request.reason,
            approver_name,  # New column
            leave_request.created_at.strftime('%d-%m-%y %H:%M'),
            leave_request.approved_at.strftime('%d-%m-%y %H:%M') if leave_request.approved_at else 'N/A'
        ])
    
    # Generate filename with filters
    filename_parts = ['leaves_export']
    
    if employee_id:
        employee = Employee.query.get(employee_id)
        filename_parts.append(f'employee_{employee.full_name.replace(" ", "_")}' if employee else 'employee_unknown')
    
    if leave_type:
        filename_parts.append(f'type_{leave_type}')
    
    if status:
        filename_parts.append(f'status_{status}')
    
    if start_date_filter:
        filename_parts.append(f'from_{start_date_filter}')
    
    if end_date_filter:
        filename_parts.append(f'to_{end_date_filter}')
    
    if days_requested:
        filename_parts.append(f'days_{days_requested}')
    
    if reason:
        filename_parts.append(f'reason_{reason.replace(" ", "_")}')
    
    filename = '_'.join(filename_parts) + '.csv'
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-type'] = 'text/csv'

    return response

@app.route('/admin_edit_leave/<int:request_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_leave(request_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to edit leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    form = LeaveRequestForm(obj=leave_request)
    
    if form.validate_on_submit():
        delta = form.end_date.data - form.start_date.data
        days_requested = delta.days + 1
        
        is_valid, error_message = validate_leave_days(form.leave_type.data, days_requested)
        
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('request_leave.html', form=form, admin_editing=True)
        
        if form.attachment.data:
            if leave_request.attachment_filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], leave_request.attachment_filename))
                except:
                    pass
            
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            filename = secure_filename(form.attachment.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            form.attachment.data.save(file_path)
            leave_request.attachment_filename = unique_filename
        
        leave_request.start_date = form.start_date.data
        leave_request.end_date = form.end_date.data
        leave_request.leave_type = form.leave_type.data
        leave_request.reason = form.reason.data
        leave_request.days_requested = days_requested
        
        db.session.commit()
        
        flash('Leave request updated successfully!', 'success')
        return redirect(url_for('all_leaves'))
    
    return render_template('request_leave.html', form=form, admin_editing=True)

@app.route('/admin_delete_leave/<int:request_id>')
@login_required
def admin_delete_leave(request_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to delete leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.attachment_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], leave_request.attachment_filename))
        except:
            pass
    
    employee_name = leave_request.employee.full_name
    leave_type = leave_request.leave_type
    
    db.session.delete(leave_request)
    db.session.commit()
    
    flash(f'Leave request for {employee_name} ({leave_type}) has been deleted successfully!', 'success')
    return redirect(url_for('all_leaves'))

@app.route('/reject_approved_leave/<int:request_id>')
@login_required
def reject_approved_leave(request_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to reject approved leaves.', 'danger')
        return redirect(url_for('all_leaves'))
    
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.status != 'approved':
        flash('Only approved leaves can be rejected.', 'danger')
        return redirect(url_for('all_leaves'))
    
    leave_request.status = 'rejected'
    leave_request.approved_at = datetime.utcnow()
    
    db.session.commit()
    
    subject = f"Your Approved Leave Request Has Been Rejected"
    body = f"""
Dear {leave_request.employee.full_name},

Your previously approved leave request has been rejected by an administrator.

Details:
- Leave Type: {leave_request.leave_type.title()}
- Start Date: {leave_request.start_date.strftime('%d-%m-%y')}
- End Date: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}

Status: Rejected (previously approved)

Please contact HR department for more information.

Thank you,
HR Department
"""
    if send_email(leave_request.employee.email, subject, body):
        flash('Approved leave request rejected. Email notification sent to employee.', 'info')
    else:
        flash('Approved leave request rejected, but failed to send email notification.', 'warning')
    
    return redirect(url_for('all_leaves'))

@app.route('/edit_leave/<int:request_id>', methods=['GET', 'POST'])
@login_required
def edit_leave(request_id):
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.employee_id != current_user.id and current_user.user_type != 'admin':
        flash('You can only edit your own leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    if leave_request.status != 'pending':
        flash('Only pending leave requests can be edited.', 'danger')
        return redirect(url_for('leaves'))
    
    form = LeaveRequestForm(obj=leave_request)
    
    if form.validate_on_submit():
        delta = form.end_date.data - form.start_date.data
        days_requested = delta.days + 1
        
        is_valid, error_message = validate_leave_days(form.leave_type.data, days_requested)
        
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('request_leave.html', form=form)
        
        if form.attachment.data:
            if leave_request.attachment_filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], leave_request.attachment_filename))
                except:
                    pass
            
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            filename = secure_filename(form.attachment.data.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            form.attachment.data.save(file_path)
            leave_request.attachment_filename = unique_filename
        
        leave_request.start_date = form.start_date.data
        leave_request.end_date = form.end_date.data
        leave_request.leave_type = form.leave_type.data
        leave_request.reason = form.reason.data
        leave_request.days_requested = days_requested
        
        db.session.commit()
        
        flash('Leave request updated successfully!', 'success')
        return redirect(url_for('leaves'))
    
    return render_template('request_leave.html', form=form, editing=True)

@app.route('/delete_leave/<int:request_id>')
@login_required
def delete_leave(request_id):
    leave_request = LeaveRequest.query.get_or_404(request_id)
    
    if leave_request.employee_id != current_user.id and current_user.user_type != 'admin':
        flash('You can only delete your own leave requests.', 'danger')
        return redirect(url_for('leaves'))
    
    if leave_request.status != 'pending' and current_user.user_type != 'admin':
        flash('Only pending leave requests can be deleted.', 'danger')
        return redirect(url_for('leaves'))
    
    if leave_request.attachment_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], leave_request.attachment_filename))
        except:
            pass
    
    db.session.delete(leave_request)
    db.session.commit()
    
    flash('Leave request deleted successfully!', 'success')
    return redirect(url_for('leaves'))

@app.route('/reset_password/<int:employee_id>', methods=['POST'])
@login_required
def reset_password(employee_id):
    if current_user.user_type != 'admin':
        flash('You do not have permission to reset passwords.', 'danger')
        return redirect(url_for('dashboard'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    characters = string.ascii_letters + string.digits
    temp_password = ''.join(random.choice(characters) for i in range(10))
    employee.password = generate_password_hash(temp_password)
    
    db.session.commit()
    
    # Get the current server URL dynamically
    server_url = request.host_url.rstrip('/')
    
    subject = "Your Hercules HR Password Has Been Reset"
    body = f"""
Dear {employee.full_name},

Your Hercules HR password has been reset by the administrator.  
Please find your updated login details below:

Username: {employee.username}  
Temporary Password: {temp_password}  

👉 For your security, please change this password immediately after logging in.

You can access the system here: {server_url}

If you run into any issues, don’t hesitate to reach out to the HR team.  

Best regards,  
Hercules HR Department
"""
    
    email_sent = send_email(employee.email, subject, body)
    
    if email_sent:
        flash('Password reset successfully. Email notification sent.', 'success')
    else:
        flash(f'Password reset successfully. New password: {temp_password}. Failed to send email.', 'warning')
    
    return redirect(url_for('manage_employees'))

@app.route('/manage_leave_balances')
@login_required
def manage_leave_balances():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to manage leave balances.', 'danger')
        return redirect(url_for('leaves'))
    
    # Get query parameters for filtering
    employee_name = request.args.get('employee_name', '').strip()
    employee_id_search = request.args.get('employee_id_search', '').strip()

    # Start with base query
    query = Employee.query

    # Apply filters
    if employee_name:
        query = query.filter(Employee.full_name.ilike(f'%{employee_name}%'))
    if employee_id_search:
        query = query.filter(Employee.employee_id.ilike(f'%{employee_id_search}%'))

    # Execute query to get filtered employees
    employees = query.all()

    return render_template('manage_leave_balances.html', employees=employees)

@app.route('/edit_leave_balance/<int:employee_id>', methods=['GET', 'POST'])
@login_required
def edit_leave_balance(employee_id):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to edit leave balances.', 'danger')
        return redirect(url_for('leaves'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Get or create leave balances
    leave_balances = {}
    for leave_type in ['annual', 'medical', 'unpaid']:
        balance = LeaveBalance.query.filter_by(employee_id=employee_id, leave_type=leave_type).first()
        if not balance:
            balance = LeaveBalance(employee_id=employee_id, leave_type=leave_type, total_days=0, used_days=0, remaining_days=0)
            db.session.add(balance)
        leave_balances[leave_type] = balance
    
    if request.method == 'POST':
        try:
            comment = request.form.get('comment', '').strip()
            
            for leave_type in ['annual', 'medical', 'unpaid']:
                balance = leave_balances[leave_type]
                
                # Get old values for history
                old_total = balance.total_days
                old_used = balance.used_days
                old_remaining = balance.remaining_days
                
                # Update with new values
                balance.total_days = int(request.form.get(f'{leave_type}_total', 0))
                balance.used_days = int(request.form.get(f'{leave_type}_used', 0))
                balance.remaining_days = int(request.form.get(f'{leave_type}_remaining', 0))
                balance.updated_at = datetime.utcnow()
                
                # Create history record if values changed
                if (old_total != balance.total_days or old_used != balance.used_days or 
                    old_remaining != balance.remaining_days):
                    history = LeaveBalanceHistory(
                        employee_id=employee_id,
                        admin_id=current_user.id,
                        leave_type=leave_type,
                        old_total=old_total,
                        new_total=balance.total_days,
                        old_used=old_used,
                        new_used=balance.used_days,
                        old_remaining=old_remaining,
                        new_remaining=balance.remaining_days,
                        comment=comment if leave_type == 'annual' else ''  # Only save comment once
                    )
                    db.session.add(history)
            
            db.session.commit()
            flash(f'Leave balances updated successfully for {employee.full_name}.', 'success')
            return redirect(url_for('manage_leave_balances'))
            
        except ValueError:
            db.session.rollback()
            flash('Invalid input. Please enter numeric values.', 'danger')
    
    return render_template('edit_leave_balance.html', employee=employee, leave_balances=leave_balances)



@login_required
def leave_balance_history():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view leave balance history.', 'danger')
        return redirect(url_for('leaves'))
    
    # Get filter parameters
    employee_id = request.args.get('employee_id', '')
    admin_id = request.args.get('admin_id', '')
    leave_type = request.args.get('leave_type', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Build query
    query = LeaveBalanceHistory.query
    
    if employee_id:
        query = query.filter(LeaveBalanceHistory.employee_id == employee_id)
    if admin_id:
        query = query.filter(LeaveBalanceHistory.admin_id == admin_id)
    if leave_type:
        query = query.filter(LeaveBalanceHistory.leave_type == leave_type)
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%d-%m-%y')
            query = query.filter(LeaveBalanceHistory.created_at >= start_date_obj)
        except ValueError:
            pass
    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%d-%m-%y')
            query = query.filter(LeaveBalanceHistory.created_at <= end_date_obj)
        except ValueError:
            pass
    
    history_records = query.order_by(LeaveBalanceHistory.created_at.desc()).all()
    employees = Employee.query.all()
    admins = Employee.query.filter(Employee.user_type.in_(['admin', 'supervisor'])).all()
    
    return render_template('leave_balance_history.html', 
                         history_records=history_records,
                         employees=employees,
                         admins=admins)

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

@app.route('/recruitment')
@login_required
def recruitment():
    return render_template('recruitment.html')

@app.route('/reports')
@login_required
def reports():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to view reports.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all employees for the filter dropdown
    if current_user.user_type == 'supervisor':
        employees = Employee.query.filter_by(supervisor_id=current_user.id).all()
    else:  # admin
        employees = Employee.query.all()
    
    # Get filter parameters
    employee_id = request.args.get('employee_id')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    status_filter = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Records per page
    
    # Convert date strings to date objects (handle both formats)
    start_date = None
    end_date = None
    
    if start_date_str:
        try:
            # Try YYYY-MM-DD format (from date input)
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            try:
                # Try DD-MM-YY format (manual entry)
                start_date = datetime.strptime(start_date_str, '%d-%m-%y').date()
            except ValueError:
                flash('Invalid start date format. Use YYYY-MM-DD or DD-MM-YY.', 'danger')
    
    if end_date_str:
        try:
            # Try YYYY-MM-DD format (from date input)
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            try:
                # Try DD-MM-YY format (manual entry)
                end_date = datetime.strptime(end_date_str, '%d-%m-%y').date()
            except ValueError:
                flash('Invalid end date format. Use YYYY-MM-DD or DD-MM-YY.', 'danger')
    
    # Default to current month if no dates provided
    if not start_date and not end_date:
        today = date.today()
        start_date = today.replace(day=1)
        end_date = today
    
    # Build query to get attendance data with additional filters for supervisors
    attendance_data = get_attendance_data(employee_id, start_date, end_date, status_filter, current_user)
    
    # Sort attendance records by date descending (newest first)
    attendance_data.sort(key=lambda x: x['date'], reverse=True)
    
    # Calculate pagination
    total_records = len(attendance_data)
    total_pages = ceil(total_records / per_page) if total_records > 0 else 1
    
    # Get records for current page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_records = attendance_data[start_idx:end_idx]
    
    # Convert dates back to string for form values
    start_date_form_value = start_date.strftime('%Y-%m-%d') if start_date else ''
    end_date_form_value = end_date.strftime('%Y-%m-%d') if end_date else ''
    
    return render_template('reports.html', 
                         employees=employees,
                         attendance_records=paginated_records,
                         now=datetime.now(),
                         current_user=current_user,
                         page=page,
                         per_page=per_page,
                         total_records=total_records,
                         total_pages=total_pages,
                         start_date_value=start_date_form_value,
                         end_date_value=end_date_form_value)

def get_attendance_data(employee_id=None, start_date=None, end_date=None, status_filter=None, current_user=None):
    """Generate attendance data for all employees based on filters"""
    
    # If no dates provided, use current month
    if not start_date:
        start_date = date.today().replace(day=1)
    if not end_date:
        end_date = date.today()
    
    # Get all employees or filtered employee with supervisor restrictions
    if employee_id:
        employee = Employee.query.get(employee_id)
        # Check if supervisor has permission to view this employee
        if current_user and current_user.user_type == 'supervisor':
            if not employee or employee.supervisor_id != current_user.id:
                return []  # No permission
        employees = [employee] if employee else []
    else:
        if current_user and current_user.user_type == 'supervisor':
            employees = Employee.query.filter_by(supervisor_id=current_user.id).all()
        else:
            employees = Employee.query.all()
    
    attendance_records = []
    
    # Get all time tracking records for the date range in one query
    time_records_query = TimeTracking.query.filter(
        TimeTracking.timestamp >= datetime.combine(start_date, datetime.min.time()),
        TimeTracking.timestamp <= datetime.combine(end_date, datetime.max.time())
    )
    
    if employee_id:
        time_records_query = time_records_query.filter(TimeTracking.employee_id == employee_id)
    elif current_user and current_user.user_type == 'supervisor':
        # Filter by supervisor's team
        team_employee_ids = [emp.id for emp in employees]
        time_records_query = time_records_query.filter(TimeTracking.employee_id.in_(team_employee_ids))
    
    time_records = time_records_query.all()
    
    # Organize records by employee and date
    records_by_employee_date = {}
    
    for record in time_records:
        record_date = record.timestamp.date()
        employee_id = record.employee_id
        
        if employee_id not in records_by_employee_date:
            records_by_employee_date[employee_id] = {}
        
        if record_date not in records_by_employee_date[employee_id]:
            records_by_employee_date[employee_id][record_date] = {
                'clock_in': None,
                'clock_out': None,
                'records': []  # Store all records for editing
            }
        
        records_by_employee_date[employee_id][record_date]['records'].append(record)
        
        if record.action_type == 'clock_in':
            # Only keep the earliest clock-in for each day
            if (records_by_employee_date[employee_id][record_date]['clock_in'] is None or 
                record.timestamp < records_by_employee_date[employee_id][record_date]['clock_in']):
                records_by_employee_date[employee_id][record_date]['clock_in'] = record.timestamp
        elif record.action_type == 'clock_out':
            # Only keep the latest clock-out for each day
            if (records_by_employee_date[employee_id][record_date]['clock_out'] is None or 
                record.timestamp > records_by_employee_date[employee_id][record_date]['clock_out']):
                records_by_employee_date[employee_id][record_date]['clock_out'] = record.timestamp
    
    # Generate attendance records - ONE record per employee per date
    for employee in employees:
        # Generate date range
        current_date = start_date
        while current_date <= end_date:
            # Check if employee has records for this date
            clock_in = None
            clock_out = None
            status = 'absent'
            total_hours = 'N/A'
            record_id = None
            
            if employee.id in records_by_employee_date and current_date in records_by_employee_date[employee.id]:
                clock_data = records_by_employee_date[employee.id][current_date]
                clock_in = clock_data['clock_in']
                clock_out = clock_data['clock_out']
                
                if clock_in:
                    status = 'present'
                    
                    # Calculate total hours if both clock in and out exist
                    if clock_in and clock_out:
                        time_diff = clock_out - clock_in
                        total_hours = round(time_diff.total_seconds() / 3600, 2)
            
            # Apply status filter
            if status_filter and status != status_filter:
                current_date += timedelta(days=1)
                continue
            
            attendance_records.append({
                'employee': employee,
                'date': current_date,
                'status': status,
                'clock_in': clock_in,
                'clock_out': clock_out,
                'total_hours': total_hours,
                'employee_id': employee.id,
                'date_str': current_date.strftime('%Y-%m-%d')
            })
            
            current_date += timedelta(days=1)
    
    return attendance_records

@app.route('/export_attendance')
@login_required
def export_attendance():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to export attendance.', 'danger')
        return redirect(url_for('reports'))
    
    # Get the same filter parameters as the reports page
    employee_id = request.args.get('employee_id')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    status_filter = request.args.get('status')
    
    # Convert date strings to date objects (handle both formats)
    start_date = None
    end_date = None
    
    if start_date_str:
        try:
            # Try YYYY-MM-DD format (from date input)
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            try:
                # Try DD-MM-YY format (manual entry)
                start_date = datetime.strptime(start_date_str, '%d-%m-%y').date()
            except ValueError:
                flash('Invalid start date format.', 'danger')
    
    if end_date_str:
        try:
            # Try YYYY-MM-DD format (from date input)
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            try:
                # Try DD-MM-YY format (manual entry)
                end_date = datetime.strptime(end_date_str, '%d-%m-%y').date()
            except ValueError:
                flash('Invalid end date format.', 'danger')
    
    # Get ALL data (not paginated) for export
    attendance_data = get_attendance_data(employee_id, start_date, end_date, status_filter, current_user)
    
    # Check if we got any data
    if not attendance_data:
        flash('No attendance records found to export.', 'warning')
        return redirect(url_for('reports'))
    
    attendance_data.sort(key=lambda x: x['date'], reverse=True)
    
    # Create CSV content as a string
    csv_content = "Employee Name,Date,Status,Clock In,Clock Out,Total Hours\n"
    
    for record in attendance_data:
        clock_in_str = record['clock_in'].strftime('%H:%M') if record['clock_in'] else 'N/A'
        clock_out_str = record['clock_out'].strftime('%H:%M') if record['clock_out'] else 'N/A'
        total_hours_str = str(record['total_hours']) if record['total_hours'] != 'N/A' else 'N/A'
        
        # Escape quotes in employee name if needed
        employee_name = record['employee'].full_name.replace('"', '""')
        
        csv_content += f'"{employee_name}",{record["date"].strftime("%d-%m-%y")},{record["status"].title()},{clock_in_str},{clock_out_str},{total_hours_str}\n'
    
    # Create response with encoded data
    response = make_response(csv_content)
    response.headers['Content-Disposition'] = f'attachment; filename=attendance_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv; charset=utf-8'
    
    return response

@app.route('/time_reports', methods=['GET'])
@login_required
def time_reports():
    now = datetime.now(MYT)
    employee_id = request.args.get('employee_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Records per page

    # Query employees for admin dropdown
    employees = Employee.query.all() if current_user.user_type == 'admin' else []

    # Base query for time records
    query = TimeTracking.query
    if current_user.user_type != 'admin':
        query = query.filter(TimeTracking.employee_id == current_user.id)
    else:
        query = query.join(Employee, TimeTracking.employee_id == Employee.id)

    # Apply filters
    if employee_id:
        query = query.filter(TimeTracking.employee_id == employee_id)
    if start_date:
        query = query.filter(func.date(TimeTracking.timestamp) >= start_date)
    if end_date:
        query = query.filter(func.date(TimeTracking.timestamp) <= end_date)
    if status:
        query = query.filter(TimeTracking.status == status)

    # Get records sorted by timestamp (newest first)
    time_records = query.order_by(TimeTracking.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('time_reports.html',
                         time_records=time_records.items,
                         employees=employees,
                         current_user=current_user,
                         page=page,
                         per_page=per_page,
                         total_records=time_records.total,
                         total_pages=time_records.pages)

@app.route('/export_time_reports', methods=['GET'])
@login_required
def export_time_reports():
    if current_user.user_type != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('time_reports'))

    now = datetime.now(MYT)
    employee_id = request.args.get('employee_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    status = request.args.get('status')

    # Base query for time records
    query = TimeTracking.query.join(Employee, TimeTracking.employee_id == Employee.id)

    # Apply filters
    if employee_id:
        query = query.filter(TimeTracking.employee_id == employee_id)
    if start_date:
        query = query.filter(func.date(TimeTracking.timestamp) >= start_date)
    if end_date:
        query = query.filter(func.date(TimeTracking.timestamp) <= end_date)
    if status:
        query = query.filter(TimeTracking.status == status)

    time_records = query.order_by(TimeTracking.timestamp.desc()).all()

    # Generate CSV using StringIO first, then convert to bytes
    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(['Employee', 'Action', 'Timestamp', 'Status', 'IP Address'])
    
    for record in time_records:
        # Handle status display
        if record.status == 'out_of_office':
            status_display = 'Out of Office'
        else:
            status_display = record.status.replace('_', ' ').title() if record.status else 'N/A'
        
        writer.writerow([
            record.employee.full_name,
            record.action_type.replace('_', ' ').title(),
            record.timestamp.astimezone(MYT).strftime('%d-%m-%y %H:%M:%S'),
            status_display,
            record.ip_address or 'N/A'
        ])
    
    # Convert to bytes
    csv_bytes = BytesIO()
    csv_bytes.write(csv_string.getvalue().encode('utf-8'))
    csv_bytes.seek(0)

    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'time_report_{now.strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/set_theme', methods=['POST'])
def set_theme():
    data = request.get_json()
    theme = data.get('theme', 'light')
    session['theme'] = theme
    return jsonify({'status': 'success'})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('settings.html', form=form)
        
        # Validate new password
        new_password = form.new_password.data
        
        # Count alphabetic characters
        letter_count = sum(1 for char in new_password if char.isalpha())
        
        if letter_count < 5:
            flash('New password must contain at least 5 letters.', 'danger')
            return render_template('settings.html', form=form)
        
        if not any(char.isdigit() for char in new_password):
            flash('New password must contain at least 1 number.', 'danger')
            return render_template('settings.html', form=form)
        
        # Update password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', form=form)

@app.route('/test')
def test_connection():
    return "Connection successful! Flask is working."

import os
import socket
import sys
from flask import cli

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

if __name__ == '__main__':
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    def get_local_ip():
        local_ip = "127.0.0.1"
        network_ip = "127.0.0.1"
        
        # Try socket connection for network IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect(("8.8.8.8", 80))
                network_ip = s.getsockname()[0]
                if network_ip.startswith("127.") or network_ip.startswith("169.254."):
                    print(f"Warning: Socket returned non-routable IP ({network_ip}). Attempting fallback.")
                    network_ip = "127.0.0.1"
        except socket.gaierror:
            print("Warning: Network IP retrieval failed: DNS resolution error (no internet?).")
        except socket.timeout:
            print("Warning: Network IP retrieval failed: Connection timed out.")
        except socket.error as e:
            print(f"Warning: Network IP retrieval failed: {str(e)}.")
        
        # Fallback to netifaces if available
        if NETIFACES_AVAILABLE and network_ip == "127.0.0.1":
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                    for addr in addrs:
                        ip = addr.get('addr')
                        if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                            network_ip = ip
                            print(f"Found network IP via netifaces: {network_ip}")
                            break
                    if network_ip != "127.0.0.1":
                        break
            except Exception as e:
                print(f"Warning: netifaces fallback failed: {str(e)}.")
        
        # Get local IP by hostname
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            socket.inet_aton(local_ip)
            if local_ip.startswith("127."):
                local_ip = "127.0.0.1"
        except (socket.gaierror, socket.error, OSError) as e:
            print(f"Warning: Local IP retrieval failed: {str(e)}. Using 127.0.0.1.")
        
        if network_ip != "127.0.0.1":
            print("Ensure firewall allows incoming connections on port 5000 for network access.")
        
        return local_ip, network_ip
    
    local_ip, network_ip = get_local_ip()
    
    print("=" * 50)
    print(f"Local access: http://{local_ip}:5000")
    print(f"Network access: http://{network_ip}:5000")
    print(f"Test connection: http://{network_ip}:5000/test")
    print("Ensure mobile devices are on the same WiFi network!")
    print("=" * 50)
    
    original_show_server_banner = cli.show_server_banner
    
    def custom_show_server_banner(*args, **kwargs):
        original_show_server_banner(*args, **kwargs)
        print(f" * Local URL: http://{local_ip}:5000")
        if network_ip != "127.0.0.1":
            print(f" * Network URL: http://{network_ip}:5000")
        else:
            print("Warning: Network access unavailable: No valid network IP detected. Check network connection or firewall.")
    
    cli.show_server_banner = custom_show_server_banner
    
    app.run(debug=True, host='0.0.0.0', port=5000)