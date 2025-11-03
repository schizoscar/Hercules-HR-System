import requests
from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_from_directory, Blueprint, send_file, session, jsonify, cli, copy_current_request_context
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import aliased
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField, HiddenField, DecimalField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date, time
from decimal import Decimal
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
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'hr.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Render/Proxy Safe Config ---
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Define Malaysia timezone
MYT = pytz.timezone('Asia/Kuala_Lumpur')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Office location for geolocation tracking (replace with actual coordinates)
OFFICE_LATITUDE = 3.2227626628735946
OFFICE_LONGITUDE = 101.56524201599817
OFFICE_RADIUS_KM = 0.5  # 100 meters radius

# Add to your app config
app.config['OFFICE_LATITUDE'] = OFFICE_LATITUDE
app.config['OFFICE_LONGITUDE'] = OFFICE_LONGITUDE
app.config['OFFICE_RADIUS_KM'] = OFFICE_RADIUS_KM

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
"""
# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'scarletsumirepoh@gmail.com'
app.config['MAIL_PASSWORD'] = 'ipfo egit wyrk uzdb'
app.config['MAIL_DEFAULT_SENDER'] = 'scarletsumirepoh.email@gmail.com'
"""

app.config['SENDGRID_API_KEY'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'itdepthercules@gmail.com'
app.config['MAIL_PASSWORD'] = 'ezjh afdo dsqa efzn'
app.config['MAIL_DEFAULT_SENDER'] = 'itdepthercules@gmail.com'

# Configuration for leave file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'attachments')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Office IP network (adjust to office's IP range)
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

def send_email_async(to, subject, body):
    """Send email in background thread to avoid timeouts"""
    @copy_current_request_context
    def send():
        try:
            # Use your existing email function or direct SMTP
            msg = Message(
                subject=subject,
                recipients=[to],
                body=body,
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            # If you're using Flask-Mail
            mail.send(msg)
            print(f"✓ Email sent to {to}")
            return True
        except Exception as e:
            print(f"✗ Failed to send email to {to}: {e}")
            return False
    
    # Start in background thread
    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()
    return True  # Return immediately

def send_email_sendgrid(to_email, subject, body):
    """Use SendGrid API with plain text formatting"""
    try:
        response = requests.post(
            'https://api.sendgrid.com/v3/mail/send',
            headers={
                'Authorization': f'Bearer {app.config["SENDGRID_API_KEY"]}',
                'Content-Type': 'application/json'
            },
            json={
                'personalizations': [{
                    'to': [{'email': to_email}]
                }],
                'from': {
                    'email': 'itdepthercules@gmail.com',
                    'name': 'Hercules HR Department'
                },
                'subject': subject,
                'content': [{
                    'type': 'text/plain',  # Use plain text to avoid link rewriting
                    'value': body
                }]
            },
            timeout=10
        )
        
        if response.status_code == 202:
            print(f"✓ Email sent to {to_email} via SendGrid")
            return True
        else:
            print(f"✗ SendGrid error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ SendGrid exception: {e}")
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
    __tablename__ = 'employee'  # Explicitly set to 'employees'
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
    
    # NEW FIELDS
    date_joined = db.Column(db.Date, nullable=True)  # Date when employee joined the company
    basic_salary = db.Column(db.Numeric(10, 2), nullable=True)  # Basic salary
    
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

class Payroll(db.Model):
    __tablename__ = 'payroll'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    pay_period = db.Column(db.String(20), nullable=False)
    basic_salary = db.Column(db.Numeric(10, 2), nullable=False)
    overtime_hours = db.Column(db.Numeric(5, 2), default=0)
    overtime_pay = db.Column(db.Numeric(10, 2), default=0)
    bonuses = db.Column(db.Numeric(10, 2), default=0)
    unpaid_leave_deduction = db.Column(db.Numeric(10, 2), default=0)
    epf_employee = db.Column(db.Numeric(10, 2), default=0)
    epf_employer = db.Column(db.Numeric(10, 2), default=0)
    socso_employee = db.Column(db.Numeric(10, 2), default=0)
    socso_employer = db.Column(db.Numeric(10, 2), default=0)
    eis_employee = db.Column(db.Numeric(10, 2), default=0)
    eis_employer = db.Column(db.Numeric(10, 2), default=0)
    tax_deduction = db.Column(db.Numeric(10, 2), default=0)
    other_deductions = db.Column(db.Numeric(10, 2), default=0)
    total_deductions = db.Column(db.Numeric(10, 2), default=0)  # Add this field
    net_salary = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    employee = db.relationship('Employee', backref='payrolls')

class PayrollSettings(db.Model):
    __tablename__ = 'payroll_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('employee.id'))

class PayrollComponent(db.Model):
    __tablename__ = 'payroll_components'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    component_type = db.Column(db.String(20), nullable=False)  # 'earning' or 'deduction'
    is_active = db.Column(db.Boolean, default=True)
    calculation_method = db.Column(db.String(50))  # 'percentage', 'fixed', 'tiered'
    default_value = db.Column(db.Numeric(10, 2), default=0)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmployeePayrollAdjustment(db.Model):
    __tablename__ = 'employee_payroll_adjustments'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    pay_period = db.Column(db.String(20), nullable=False)  # YYYY-MM format
    adjustment_type = db.Column(db.String(50), nullable=False)  # 'bonus', 'overtime', 'deduction', etc.
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('employee.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref='payroll_adjustments')
    creator = db.relationship('Employee', foreign_keys=[created_by])

class PayrollAuditTrail(db.Model):
    __tablename__ = 'payroll_audit_trail'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    pay_period = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # 'bonus_added', 'overtime_adjusted', etc.
    field_name = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.String(255))
    new_value = db.Column(db.String(255))
    comment = db.Column(db.Text)
    performed_by = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref='payroll_audits')
    performer = db.relationship('Employee', foreign_keys=[performed_by])

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
    nationality = StringField('Nationality', validators=[DataRequired()])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[
        ('employee', 'Employee'),
        ('supervisor', 'Supervisor'),
        ('admin', 'Admin'),
        ('factory', 'Factory Worker')
    ], validators=[DataRequired()])
    # NEW FIELDS
    date_joined = DateField('Date Joined', format='%Y-%m-%d', validators=[DataRequired()])
    basic_salary = DecimalField('Basic Salary', validators=[DataRequired()])
    submit = SubmitField('Add Employee')

class BulkAddEmployeesForm(FlaskForm):
    employee_data = TextAreaField('Employee Data', validators=[DataRequired()], 
        render_kw={'placeholder': 'Format: Full Name,Email,Nationality,Employee ID,User Type,Date Joined (YYYY-MM-DD),Basic Salary\nExample: John Doe,john@company.com,Malaysian,EMP1001,employee,2024-01-15,3500.00'})
    submit = SubmitField('Add Employees')

class EditEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    nationality = StringField('Nationality', validators=[DataRequired()])
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[
        ('employee', 'Employee'),
        ('supervisor', 'Supervisor'),
        ('admin', 'Admin'),
        ('factory', 'Factory Worker')
    ], validators=[DataRequired()])
    date_joined = DateField('Date Joined', format='%Y-%m-%d', validators=[DataRequired()])
    basic_salary = DecimalField('Basic Salary', validators=[DataRequired()])
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
        ('unpaid', 'Unpaid Leave'),
        ('maternity', 'Maternity Leave'),
        ('compassionate', 'Compassionate Leave'),
        ('marriage', 'Marriage Leave'),
        ('hospitalized', 'Hospitalized Leave'),
        ('socso_mc', 'Socso MC')
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
        for leave_type in ['annual', 'unpaid', 'maternity', 'compassionate', 'marriage', 'hospitalized', 'socso_mc']:
            balance = LeaveBalance.query.filter_by(
                employee_id=employee.id, 
                leave_type=leave_type
            ).first()
            
            if not balance:
                # Calculate annual leave based on date_joined if available
                if leave_type == 'annual':
                    if employee.date_joined:
                        default_days = calculate_annual_leave_days(employee.date_joined)
                    else:
                        default_days = 20  # Default for existing employees without date_joined
                elif leave_type == 'medical':
                    default_days = 14
                elif leave_type == 'maternity':
                    default_days = 90
                elif leave_type == 'compassionate':
                    default_days = 3
                elif leave_type == 'marriage':
                    default_days = 3
                elif leave_type == 'hospitalized':
                    default_days = 60
                elif leave_type == 'socso_mc':
                    default_days = 14
                else:  # unpaid and others
                    default_days = 0
                
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

"""
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
                host = self.headers.get('Host', 'localhost:8888')
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
"""
def validate_leave_days(leave_type, days_requested):
    """Validate if the requested leave days are within allowed limits"""
    max_limits = {
        'medical': 14,
        'maternity': 90,
        'compassionate': 3,
        'marriage': 3,
        'hospitalized': 60,
        'socso_mc': 14
    }
    
    if leave_type in max_limits:
        if days_requested > max_limits[leave_type]:
            return False, f"Maximum {max_limits[leave_type]} days allowed for {leave_type.replace('_', ' ').title()} Leave"
    
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

@app.route('/test')
def test():
    session['test'] = 'ok'
    return f"Session works: {session.get('test')}"

@app.route('/create_test_users')
def create_test_users():
    if not Employee.query.filter_by(username='admin').first():
        admin_user = Employee(
            username='admin1',
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

        # Convert latitude/longitude to float if provided, else None
        try:
            latitude = float(latitude) if latitude else None
            longitude = float(longitude) if longitude else None
        except (ValueError, TypeError):
            latitude = None
            longitude = None

        # SMART STATUS DETERMINATION: Use geolocation if available, otherwise fallback to IP
        if latitude and longitude:
            # Use precise geolocation coordinates
            status = 'in_office' if is_in_office(latitude, longitude) else 'out_of_office'
            location_source = "geolocation"
        else:
            # Fallback to IP-based detection when location is denied/unavailable
            status = 'in_office' if is_ip_in_office_network(ip_address) else 'out_of_office'
            location_source = "IP"

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
                    latitude=latitude,
                    longitude=longitude,
                    address=address if address else 'Auto-ended at clock-out',
                    ip_address=ip_address,
                    status=status
                )
                db.session.add(lunch_end_entry)
                flash('Lunch automatically ended at clock-out', 'info')
                
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
            
            # CRITICAL FIX: Prevent lunch start after clock out
            if latest_clock_out:
                db.session.rollback()
                flash('Cannot start lunch: You have already clocked out today.', 'danger')
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
            
            # Also prevent lunch end after clock out
            if latest_clock_out:
                db.session.rollback()
                flash('Cannot end lunch: You have already clocked out today.', 'danger')
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
            latitude=latitude,
            longitude=longitude,
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
            
            # Smart success message based on location source
            if location_source == "geolocation":
                location_info = " (location verified)"
            else:
                location_info = " (general location)"
                
            flash(f'Successfully {action_type.replace("_", " ")}{location_info}!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error during {action_type.replace("_", " ")}: {str(e)}', 'danger')
    else:
        flash('Invalid form submission.', 'danger')
    
    return redirect(url_for('dashboard'))

def is_in_office(latitude, longitude, accuracy=None):
    """Check if coordinates are within office boundaries using geolocation."""
    if not latitude or not longitude:
        return False
    
    try:
        # Office coordinates (replace with your actual office coordinates)
        OFFICE_LATITUDE = 3.2227626628735946  # Your office latitude
        OFFICE_LONGITUDE = 101.56524201599817  # Your office longitude
        
        # Office radius in kilometers
        OFFICE_RADIUS_KM = 0.1  # 100 meters radius
        
        # Calculate distance using Haversine formula
        from math import radians, sin, cos, sqrt, atan2
        
        lat1 = radians(OFFICE_LATITUDE)
        lon1 = radians(OFFICE_LONGITUDE)
        lat2 = radians(float(latitude))
        lon2 = radians(float(longitude))
        
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance_km = 6371 * c  # Earth radius in km
        
        # Consider accuracy margin
        accuracy_margin = (accuracy or 50) / 1000  # Convert meters to km
        
        return distance_km <= (OFFICE_RADIUS_KM + accuracy_margin)
        
    except (ValueError, TypeError) as e:
        print(f"Error calculating office proximity: {e}")
        return False

def is_ip_in_office_network(ip_address):
    """Check if the IP address is within the office network range."""
    try:
        ip = ipaddress.ip_address(ip_address)
        office_network = ipaddress.ip_network(app.config['OFFICE_NETWORK'], strict=False)
        return ip in office_network
    except ValueError:
        return False

def can_perform_time_action(employee, action_type):
    """Check if employee can perform the requested time action"""
    now = datetime.utcnow()
    today = now.date()
    
    # Get today's actual records from database, not just last timestamps
    today_clock_in = TimeTracking.query.filter(
        TimeTracking.employee_id == employee.id,
        TimeTracking.action_type == 'clock_in',
        db.func.date(TimeTracking.timestamp) == today
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    today_clock_out = TimeTracking.query.filter(
        TimeTracking.employee_id == employee.id,
        TimeTracking.action_type == 'clock_out', 
        db.func.date(TimeTracking.timestamp) == today
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    today_lunch_start = TimeTracking.query.filter(
        TimeTracking.employee_id == employee.id,
        TimeTracking.action_type == 'lunch_start',
        db.func.date(TimeTracking.timestamp) == today
    ).order_by(TimeTracking.timestamp.desc()).first()
    
    today_lunch_end = TimeTracking.query.filter(
        TimeTracking.employee_id == employee.id,
        TimeTracking.action_type == 'lunch_end',
        db.func.date(TimeTracking.timestamp) == today
    ).order_by(TimeTracking.timestamp.desc()).first()

    if action_type == 'clock_in':
        if today_clock_in:
            return False, 'You have already clocked in today.'
        return True, ''
    
    elif action_type == 'clock_out':
        if not today_clock_in:
            return False, 'You must clock in first.'
        if today_clock_out:
            return False, 'You have already clocked out today.'
        return True, ''
    
    elif action_type == 'lunch_start':
        # CRITICAL: Cannot start lunch if already clocked out
        if today_clock_out:
            return False, 'Cannot start lunch: You have already clocked out today.'
        if not today_clock_in:
            return False, 'Cannot start lunch: No clock-in found for today.'
        if today_lunch_start and not today_lunch_end:
            return False, 'Cannot start lunch: Lunch already started.'
        if today_lunch_start and today_lunch_end:
            return False, 'Cannot start lunch: Lunch already completed for today.'
        return True, ''
    
    elif action_type == 'lunch_end':
        if not today_lunch_start:
            return False, 'No lunch start record found for today.'
        if today_lunch_end:
            return False, 'You have already ended lunch today.'
        # CRITICAL: Cannot end lunch if already clocked out
        if today_clock_out:
            return False, 'Cannot end lunch: You have already clocked out today.'
        return True, ''
    
    return False, 'Invalid action.'

@app.route('/geolocation')
@login_required
def geolocation_page():
    """Serve a same-origin iframe that can access geolocation with better UX"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Geolocation</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                margin: 0;
                padding: 20px;
                font-family: Arial, sans-serif;
                background: transparent;
                color: #333;
            }
            .location-message {
                text-align: center;
                font-size: 14px;
                line-height: 1.4;
            }
            .success { color: #28a745; }
            .error { color: #dc3545; }
            .info { color: #17a2b8; }
        </style>
    </head>
    <body>
        <div id="status" class="location-message info">
            🔄 Requesting location access...
        </div>

        <script>
            function sendGeolocationToParent(coords, error = null) {
                window.parent.postMessage({
                    type: error ? 'geolocation_error' : 'geolocation_success',
                    coords: coords,
                    error: error
                }, window.location.origin);
            }

            function updateStatus(message, type = 'info') {
                const statusEl = document.getElementById('status');
                statusEl.textContent = message;
                statusEl.className = `location-message ${type}`;
            }

            // Try to get location with user-friendly messages
            if (navigator.geolocation) {
                updateStatus('📍 Please allow location access for time tracking...', 'info');
                
                navigator.geolocation.getCurrentPosition(
                    function(position) {
                        updateStatus('✅ Location access granted!', 'success');
                        sendGeolocationToParent({
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy,
                            timestamp: new Date().toISOString()
                        });
                    },
                    function(error) {
                        let errorMessage, userMessage;
                        switch(error.code) {
                            case error.PERMISSION_DENIED:
                                errorMessage = 'Location access denied by user';
                                userMessage = '❌ Location access denied. Time tracking will work without precise location.';
                                break;
                            case error.POSITION_UNAVAILABLE:
                                errorMessage = 'Location information unavailable';
                                userMessage = '❌ Location unavailable. Time tracking will work without precise location.';
                                break;
                            case error.TIMEOUT:
                                errorMessage = 'Location request timed out';
                                userMessage = '⏰ Location request timed out. Time tracking will work without precise location.';
                                break;
                            default:
                                errorMessage = 'Unknown geolocation error';
                                userMessage = '❌ Location error. Time tracking will work without precise location.';
                        }
                        updateStatus(userMessage, 'error');
                        sendGeolocationToParent(null, errorMessage);
                    },
                    {
                        enableHighAccuracy: false,  // Changed to false for better acceptance
                        timeout: 10000,
                        maximumAge: 300000  // 5 minutes cache
                    }
                );
            } else {
                updateStatus('❌ Geolocation not supported by your browser', 'error');
                sendGeolocationToParent(null, 'Geolocation not supported by browser');
            }
        </script>
    </body>
    </html>
    """

def is_in_office(latitude, longitude, accuracy=None):
    """Check if coordinates are within office boundaries using geolocation."""
    if not latitude or not longitude:
        return False
    
    try:
        # Get office coordinates from config
        OFFICE_LATITUDE = app.config['OFFICE_LATITUDE']
        OFFICE_LONGITUDE = app.config['OFFICE_LONGITUDE']
        OFFICE_RADIUS_KM = app.config['OFFICE_RADIUS_KM']
        
        # Calculate distance using Haversine formula
        from math import radians, sin, cos, sqrt, atan2
        
        lat1 = radians(OFFICE_LATITUDE)
        lon1 = radians(OFFICE_LONGITUDE)
        lat2 = radians(float(latitude))
        lon2 = radians(float(longitude))
        
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance_km = 6371 * c  # Earth radius in km
        
        # Consider accuracy margin
        accuracy_margin = (accuracy or 50) / 1000  # Convert meters to km
        
        return distance_km <= (OFFICE_RADIUS_KM + accuracy_margin)
        
    except (ValueError, TypeError) as e:
        print(f"Error calculating office proximity: {e}")
        return False

def calculate_annual_leave_days(date_joined):
    """Calculate annual leave days based on years of service"""
    if not date_joined:
        return 20  # Default for existing employees
    
    today = date.today()
    years_of_service = today.year - date_joined.year
    
    # Adjust if anniversary hasn't occurred this year
    if today.month < date_joined.month or (today.month == date_joined.month and today.day < date_joined.day):
        years_of_service -= 1
    
    if years_of_service < 2:
        return 8
    elif 2 <= years_of_service < 5:
        return 12
    else:  # 5 years or more
        return 16

def calculate_unpaid_leave_deduction(salary, unpaid_days):
    """Calculate unpaid leave deduction based on working days"""
    settings = get_payroll_settings()
    
    # Safely get working days - handle the case where it might be a boolean
    working_days_value = settings.get('working_days_per_month', 26)
    
    # Convert to Decimal safely
    if isinstance(working_days_value, bool):
        working_days = Decimal('26')  # Default value if it's a boolean
    else:
        try:
            working_days = Decimal(str(working_days_value))
        except:
            working_days = Decimal('26')  # Fallback to default
    
    daily_rate = salary / working_days
    return round(daily_rate * Decimal(str(unpaid_days)), 2)

@app.route('/admin/email_gone_online_test')
@login_required
def email_gone_online_test():
    if current_user.user_type != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    # Find your test employee
    test_employee = Employee.query.filter_by(email="scarletsumirepoh@gmail.com").first()
    if not test_employee:
        flash('Test employee not found.', 'danger')
        return redirect(url_for('dashboard'))

    server_url = "https://hercules-hr-system.onrender.com/"

    # Generate temp password only for test employee
    temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
    test_employee.password = generate_password_hash(temp_password)

    try:
        db.session.commit()
        
        subject = "🎉 Hercules HR System is Live!"
        body = f"""
Dear {test_employee.full_name},

Great news! The Hercules HR System is now online and accessible from anywhere! Your password has been reset for security purposes. Please log in and update your password in the settings.

🔗 Your New Login Portal:
{server_url}

👤 Your Login Details:
• Username: {test_employee.username}
• Temporary Password: {temp_password}

🚀 What's New:
• Access the system from any device with internet
• No more local network restrictions
• Same great features, now with more flexibility

📱 Access Anywhere:
You can now access the system from:
• Office computers
• Home laptops
• Mobile phones
• Tablets

If you experience any issues accessing the system or have questions, please contact the HR department.

Best regards,
Hercules IT Department
"""
        # Send using SendGrid
        email_sent = send_email_sendgrid(test_employee.email, subject, body)
        
        if email_sent:
            flash(f'Test email sent successfully to {test_employee.email}', 'success')
        else:
            flash(f'Failed to send test email to {test_employee.email}', 'warning')
            
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to reset password: {str(e)}", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/admin/email_gone_online')
@login_required
def email_gone_online():
    if current_user.user_type != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    employees = Employee.query.all()
    if not employees:
        flash('No employees found to email.', 'warning')
        return redirect(url_for('dashboard'))

    server_url = "https://hercules-hr-system.onrender.com/"  # public URL

    temp_passwords = {}
    reset_count = 0
    email_success_count = 0
    email_failed_count = 0

    # Step 1: Generate temporary passwords and update DB
    for employee in employees:
        temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        employee.password = generate_password_hash(temp_password)
        temp_passwords[employee.id] = temp_password
        reset_count += 1

    # Commit all password changes at once
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to reset passwords: {str(e)}", 'danger')
        return redirect(url_for('dashboard'))

    # Step 2: Send emails
    for employee in employees:
        try:
            temp_password = temp_passwords[employee.id]
            subject = "🎉 Hercules HR System is Live!"
            body = f"""
Dear {employee.full_name},

Great news! The Hercules HR System is now online and accessible from anywhere! Your password has been reset for security purposes. Please log in and update your password in the settings.

🔗 Your New Login Portal:
{server_url}

👤 Your Login Details:
• Username: {employee.username}
• Temporary Password: {temp_password}

🚀 What's New:
• Access the system from any device with internet
• No more local network restrictions
• Same great features, now with more flexibility

📱 Access Anywhere:
You can now access the system from:
• Office computers
• Home laptops
• Mobile phones
• Tablets

If you experience any issues accessing the system or have questions, please contact the HR department.

Best regards,
Hercules IT Department
"""
            email_sent = send_email(employee.email, subject, body)
            if email_sent:
                email_success_count += 1
                print(f"✓ Email sent to {employee.email}")
            else:
                email_failed_count += 1
                print(f"✗ Failed to send email to {employee.email}")

        except Exception as e:
            print(f"Error sending email to {employee.email}: {e}")
            email_failed_count += 1
            continue

    # Flash summary
    flash_message = f"""
Password reset and emailing completed!
• {reset_count} passwords reset
• {email_success_count} emails sent successfully
• {email_failed_count} emails failed
"""
    if email_failed_count > 0:
        flash(flash_message, 'warning')
    else:
        flash(flash_message, 'success')

    return redirect(url_for('dashboard'))

@app.route('/reset_admin_password')
def reset_admin_password():
    admin_user = Employee.query.filter_by(username='admin').first()
    
    if not admin_user:
        flash("Admin user not found.", "danger")
        return redirect(url_for('dashboard'))
    
    # Generate new temporary password
    characters = string.ascii_letters + string.digits
    temp_password = ''.join(random.choice(characters) for i in range(10))
    admin_user.password = generate_password_hash(temp_password)
    
    try:
        db.session.commit()
        flash(f"Admin password reset successfully. New password: {temp_password}", "success")
        
        # Optional: send email to admin
        # send_email(admin_user.email, "Admin Password Reset", f"Your new password is: {temp_password}")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error resetting admin password: {str(e)}", "danger")
    
    return redirect(url_for('dashboard'))

@app.route('/payroll')
@login_required
def payroll():
    if current_user.user_type != 'admin':
        flash('You do not have permission to view payroll.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        print("Starting payroll calculation...")  # Debug
        
        # Get current month and year for payroll period
        current_date = datetime.now()
        current_period = current_date.strftime('%Y-%m')
        current_period_display = current_date.strftime('%B %Y')
        
        # Get filter parameters
        employee_search = request.args.get('employee_search', '')
        filter_month = request.args.get('month', type=int)
        filter_year = request.args.get('year', type=int)
        
        print(f"Filters - search: {employee_search}, month: {filter_month}, year: {filter_year}")  # Debug
        
        # Build query for employees
        employees_query = Employee.query
        
        # Apply filters
        if employee_search:
            employees_query = employees_query.filter(Employee.full_name.ilike(f'%{employee_search}%'))
        
        # Get all employees with their basic salary
        employees_query = employees_query.order_by(Employee.full_name.asc())
        employees = employees_query.all()
        
        print(f"Found {len(employees)} employees")  # Debug
        
        # Calculate payroll for each employee
        payroll_data = []
        period_display = current_period_display  # Initialize with current period
        
        for i, employee in enumerate(employees):
            print(f"Processing employee {i+1}/{len(employees)}: {employee.full_name}")  # Debug
            
            if employee.basic_salary:
                # Determine which period to use for calculation
                if filter_month and filter_year:
                    pay_period = f"{filter_year}-{filter_month:02d}"
                    period_display = f"{datetime(filter_year, filter_month, 1).strftime('%B %Y')}"
                else:
                    pay_period = current_period
                    period_display = current_period_display
                
                print(f"Calculating payroll for period: {pay_period}")  # Debug
                
                try:
                    payroll_info = calculate_monthly_payroll(employee, pay_period)
                    payroll_info['employee_data'] = {
                        'id': employee.id,
                        'full_name': employee.full_name,
                        'employee_id': employee.employee_id,
                        'basic_salary': float(employee.basic_salary) if employee.basic_salary else 0,
                        'nationality': employee.nationality
                    }
                    payroll_data.append(payroll_info)
                    print(f"Successfully calculated payroll for {employee.full_name}")  # Debug
                except Exception as e:
                    print(f"Error calculating payroll for {employee.full_name}: {str(e)}")  # Debug
                    # Continue with other employees even if one fails
                    continue
        
        print(f"Successfully calculated payroll for {len(payroll_data)} employees")  # Debug
        
        # Generate month names for the filter dropdown
        months = []
        for i in range(1, 13):
            months.append({
                'value': i,
                'name': datetime(2023, i, 1).strftime('%B')
            })
        
        # Generate years for the filter dropdown
        years = list(range(2020, 2031))
        
        return render_template('payroll.html', 
                             payroll_data=payroll_data,
                             current_period=current_period,
                             current_period_display=period_display,
                             employees=employees,
                             months=months,
                             years=years,
                             filter_month=filter_month,
                             filter_year=filter_year,
                             employee_search=employee_search)
    
    except Exception as e:
        print(f"Critical error in payroll route: {str(e)}")  # Debug
        import traceback
        traceback.print_exc()
        flash(f'Error loading payroll: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/payroll/adjustments', methods=['POST'])
@login_required
def add_payroll_adjustment():
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    try:
        data = request.get_json()
        employee_id = data.get('employee_id')
        pay_period = data.get('pay_period')
        adjustment_type = data.get('adjustment_type')
        amount = data.get('amount')
        description = data.get('description', '')
        
        # Create adjustment
        adjustment = EmployeePayrollAdjustment(
            employee_id=employee_id,
            pay_period=pay_period,
            adjustment_type=adjustment_type,
            amount=amount,
            description=description,
            created_by=current_user.id
        )
        
        db.session.add(adjustment)
        
        # Create audit trail entry
        audit = PayrollAuditTrail(
            employee_id=employee_id,
            pay_period=pay_period,
            action=f'{adjustment_type}_added',
            field_name=adjustment_type,
            old_value='0.00',
            new_value=str(amount),
            comment=description,
            performed_by=current_user.id
        )
        
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Adjustment added successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/payroll/adjustments/<int:employee_id>/<pay_period>')
@login_required
def get_employee_adjustments(employee_id, pay_period):
    if current_user.user_type != 'admin':
        return jsonify([]), 403
    
    adjustments = EmployeePayrollAdjustment.query.filter_by(
        employee_id=employee_id,
        pay_period=pay_period
    ).all()
    
    adjustments_data = []
    for adjustment in adjustments:
        adjustments_data.append({
            'id': adjustment.id,
            'adjustment_type': adjustment.adjustment_type,
            'amount': float(adjustment.amount),
            'description': adjustment.description,
            'created_at': adjustment.created_at.isoformat()
        })
    
    return jsonify(adjustments_data)

@app.route('/payroll/adjustments/<int:adjustment_id>', methods=['DELETE'])
@login_required
def delete_payroll_adjustment(adjustment_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    try:
        adjustment = EmployeePayrollAdjustment.query.get_or_404(adjustment_id)
        
        # Create audit trail entry before deletion
        audit = PayrollAuditTrail(
            employee_id=adjustment.employee_id,
            pay_period=adjustment.pay_period,
            action=f'{adjustment.adjustment_type}_removed',
            field_name=adjustment.adjustment_type,
            old_value=str(adjustment.amount),
            new_value='0.00',
            comment=f'Removed adjustment: {adjustment.description}',
            performed_by=current_user.id
        )
        
        db.session.add(audit)
        db.session.delete(adjustment)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Adjustment removed successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/payroll/audit-trail')
@login_required
def payroll_audit_trail():
    if current_user.user_type != 'admin':
        flash('You do not have permission to view audit trail.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get filter parameters
    employee_id = request.args.get('employee_id', type=int)
    pay_period = request.args.get('pay_period', '')
    
    # Build query
    audit_query = PayrollAuditTrail.query.join(Employee, PayrollAuditTrail.employee_id == Employee.id)
    
    if employee_id:
        audit_query = audit_query.filter(PayrollAuditTrail.employee_id == employee_id)
    
    if pay_period:
        audit_query = audit_query.filter(PayrollAuditTrail.pay_period == pay_period)
    
    audit_entries = audit_query.order_by(PayrollAuditTrail.performed_at.desc()).all()
    
    return render_template('payroll_audit.html', audit_entries=audit_entries)

@app.route('/payroll/generate', methods=['POST'])
@login_required
def generate_payroll():
    if current_user.user_type != 'admin':
        flash('You do not have permission to generate payroll.', 'danger')
        return redirect(url_for('dashboard'))
    
    pay_period = request.form.get('pay_period')
    
    # Get all employees with basic salary
    employees = Employee.query.filter(Employee.basic_salary.isnot(None)).all()
    
    payroll_records = []
    for employee in employees:
        payroll_info = calculate_monthly_payroll(employee, pay_period)
        
        # Calculate total_deductions
        total_deductions = (payroll_info['unpaid_leave_deduction'] + 
                           payroll_info['epf_employee'] + 
                           payroll_info['socso_employee'] + 
                           payroll_info['eis_employee'] + 
                           payroll_info['tax_deduction'] + 
                           payroll_info['other_deductions'])
        
        # Create payroll record
        payroll = Payroll(
            employee_id=employee.id,
            pay_period=pay_period,
            basic_salary=payroll_info['basic_salary'],
            overtime_hours=payroll_info['overtime_hours'],
            overtime_pay=payroll_info['overtime_pay'],
            bonuses=payroll_info['bonuses'],
            unpaid_leave_deduction=payroll_info['unpaid_leave_deduction'],
            epf_employee=payroll_info['epf_employee'],
            epf_employer=payroll_info['epf_employer'],
            socso_employee=payroll_info['socso_employee'],
            socso_employer=payroll_info['socso_employer'],
            eis_employee=payroll_info['eis_employee'],
            eis_employer=payroll_info['eis_employer'],
            tax_deduction=payroll_info['tax_deduction'],
            other_deductions=payroll_info['other_deductions'],
            total_deductions=total_deductions,  
            net_salary=payroll_info['net_salary'],
            status='processed',
            processed_at=datetime.utcnow()
        )
        payroll_records.append(payroll)
    
    # Add all records to database
    db.session.add_all(payroll_records)
    db.session.commit()
    
    flash(f'Payroll generated successfully for {pay_period}!', 'success')
    return redirect(url_for('payroll'))

@app.route('/payroll/history')
@login_required
def payroll_history():
    if current_user.user_type != 'admin':
        flash('You do not have permission to view payroll history.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all payroll records grouped by period
    payroll_periods = db.session.query(Payroll.pay_period).distinct().order_by(Payroll.pay_period.desc()).all()
    
    selected_period = request.args.get('period')
    payroll_data = []
    
    if selected_period:
        # Get payroll for specific period
        payroll_data = Payroll.query.filter_by(pay_period=selected_period).join(Employee).order_by(Employee.full_name.asc()).all()
    
    return render_template('payroll_history.html',
                         payroll_periods=payroll_periods,
                         selected_period=selected_period,
                         payroll_data=payroll_data)

@app.route('/payroll/export/<period>')
@login_required
def export_payroll(period):
    if current_user.user_type != 'admin':
        flash('You do not have permission to export payroll.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get filter parameters from request
    employee_search = request.args.get('employee_search', '')
    filter_month = request.args.get('month', type=int)
    filter_year = request.args.get('year', type=int)
    
    # Build query based on filters (same logic as payroll route)
    employees_query = Employee.query
    
    if employee_search:
        employees_query = employees_query.filter(Employee.full_name.ilike(f'%{employee_search}%'))
    
    employees_query = employees_query.order_by(Employee.full_name.asc())
    employees = employees_query.all()
    
    # Calculate payroll data with same filters
    payroll_data = []
    for employee in employees:
        if employee.basic_salary:
            # Use the same period logic as the payroll page
            if filter_month and filter_year:
                pay_period = f"{filter_year}-{filter_month:02d}"
            else:
                pay_period = period
            
            payroll_info = calculate_monthly_payroll(employee, pay_period)
            payroll_info['employee_data'] = {
                'id': employee.id,
                'full_name': employee.full_name,
                'employee_id': employee.employee_id,
                'basic_salary': float(employee.basic_salary) if employee.basic_salary else 0,
                'nationality': employee.nationality
            }
            payroll_data.append(payroll_info)
    
    # Create CSV content with filtered data
    csv_content = "Employee Name,Employee ID,Nationality,Basic Salary,Overtime Hours,Overtime Pay,Bonuses,Unpaid Leave Deduction,EPF Employee,SOCSO Employee,EIS Employee,Tax Deduction,Other Deductions,Total Deductions,Net Salary\n"
    
    for payroll in payroll_data:
        csv_content += f'"{payroll["employee_data"]["full_name"]}",'
        csv_content += f'"{payroll["employee_data"]["employee_id"]}",'
        csv_content += f'"{payroll["employee_data"]["nationality"]}",'
        csv_content += f'{payroll["basic_salary"]},'
        csv_content += f'{payroll["overtime_hours"]},'
        csv_content += f'{payroll["overtime_pay"]},'
        csv_content += f'{payroll["bonuses"]},'
        csv_content += f'{payroll["unpaid_leave_deduction"]},'
        csv_content += f'{payroll["epf_employee"]},'
        csv_content += f'{payroll["socso_employee"]},'
        csv_content += f'{payroll["eis_employee"]},'
        csv_content += f'{payroll["tax_deduction"]},'
        csv_content += f'{payroll["other_deductions"]},'
        csv_content += f'{payroll["total_deductions"]},'
        csv_content += f'{payroll["net_salary"]}\n'
    
    # Create filename with filter info
    filename = f"payroll_{period}"
    if employee_search:
        filename += f"_search_{employee_search[:20]}"
    if filter_month:
        filename += f"_month_{filter_month}"
    if filter_year:
        filename += f"_year_{filter_year}"
    filename += ".csv"
    
    response = make_response(csv_content)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-type'] = 'text/csv'
    
    return response
def safe_decimal_convert(value, default=0):
    """Safely convert a value to Decimal, handling various types"""
    if isinstance(value, bool):
        return Decimal(str(default))
    try:
        return Decimal(str(value))
    except:
        return Decimal(str(default))

def calculate_monthly_payroll(employee, pay_period):
    """Calculate monthly payroll for an employee with database settings and individual adjustments"""
    try:
        basic_salary = employee.basic_salary or Decimal('0')
        
        # Get calculation settings from database
        settings = get_payroll_settings()
        
        # Initialize all components to 0
        overtime_pay = Decimal('0')
        bonuses = Decimal('0')
        unpaid_deduction = Decimal('0')
        epf_employee = Decimal('0')
        epf_employer = Decimal('0')
        socso_employee = Decimal('0')
        socso_employer = Decimal('0')
        eis_employee = Decimal('0')
        eis_employer = Decimal('0')
        tax_deduction = Decimal('0')
        other_deductions = Decimal('0')
        overtime_hours = Decimal('0')
        
        # Get individual adjustments for this employee and period
        adjustments = EmployeePayrollAdjustment.query.filter_by(
            employee_id=employee.id,
            pay_period=pay_period
        ).all()
        
        # Apply individual adjustments
        individual_bonus = Decimal('0')
        individual_overtime = Decimal('0')
        individual_other_deductions = Decimal('0')
        
        for adjustment in adjustments:
            if adjustment.adjustment_type == 'bonus':
                individual_bonus += adjustment.amount
            elif adjustment.adjustment_type == 'overtime':
                individual_overtime += adjustment.amount
            elif adjustment.adjustment_type == 'other_deduction':
                individual_other_deductions += adjustment.amount
        
        # Calculate components based on settings
        if settings.get('include_unpaid_leave', True):
            unpaid_deduction = calculate_unpaid_leave_for_period(employee.id, pay_period)
        
        # Check if employee is Malaysian for SOCSO
        is_malaysian = employee.nationality and employee.nationality.lower() in ['malaysian', 'malaysia']
        
        if settings.get('include_epf', True):
            epf_rate_employee = safe_decimal_convert(settings.get('epf_employee_rate', 11.0)) / Decimal('100')
            epf_rate_employer = safe_decimal_convert(settings.get('epf_employer_rate', 13.0)) / Decimal('100')
            epf_employee = round(basic_salary * epf_rate_employee, 2)
            epf_employer = round(basic_salary * epf_rate_employer, 2)
        
        if settings.get('include_socso', True) and is_malaysian:
            if basic_salary <= Decimal('5000'):
                socso_employee = safe_decimal_convert(settings.get('socso_employee_low', 0.50))
                socso_employer = safe_decimal_convert(settings.get('socso_employer_low', 0.70))
            else:
                socso_employee = safe_decimal_convert(settings.get('socso_employee_high', 1.00))
                socso_employer = safe_decimal_convert(settings.get('socso_employer_high', 1.20))
        
        if settings.get('include_eis', True) and is_malaysian:
            eis_rate_employee = safe_decimal_convert(settings.get('eis_employee_rate', 0.5)) / Decimal('100')
            eis_rate_employer = safe_decimal_convert(settings.get('eis_employer_rate', 0.7)) / Decimal('100')
            eis_employee = round(basic_salary * eis_rate_employee, 2)
            eis_employer = round(basic_salary * eis_rate_employer, 2)
        
        if settings.get('include_tax', True):
            tax_deduction = calculate_tax_deduction(basic_salary)
        
        # Apply individual adjustments to calculations
        if settings.get('include_overtime', True):
            overtime_rate = safe_decimal_convert(settings.get('overtime_rate', 15.00))
            calculated_overtime_hours = calculate_overtime_hours(employee.id, pay_period)
            calculated_overtime_pay = calculated_overtime_hours * overtime_rate
            overtime_pay = calculated_overtime_pay + individual_overtime
            overtime_hours = calculated_overtime_hours + (individual_overtime / overtime_rate if overtime_rate > 0 else Decimal('0'))
        
        if settings.get('include_bonuses', True):
            default_bonus = safe_decimal_convert(settings.get('bonus_amount', 0.00))
            bonuses = default_bonus + individual_bonus
        
        if settings.get('include_other_deductions', True):
            default_other_deductions = safe_decimal_convert(settings.get('other_deductions_amount', 0.00))
            other_deductions = default_other_deductions + individual_other_deductions
        
        # Calculate total deductions and net salary
        total_deductions = (unpaid_deduction + epf_employee + socso_employee + 
                           eis_employee + tax_deduction + other_deductions)
        
        total_earnings = basic_salary + overtime_pay + bonuses
        net_salary = total_earnings - total_deductions
        
        return {
            'basic_salary': float(basic_salary),
            'overtime_hours': float(overtime_hours),
            'overtime_pay': float(overtime_pay),
            'bonuses': float(bonuses),
            'unpaid_leave_deduction': float(unpaid_deduction),
            'epf_employee': float(epf_employee),
            'epf_employer': float(epf_employer),
            'socso_employee': float(socso_employee),
            'socso_employer': float(socso_employer),
            'eis_employee': float(eis_employee),
            'eis_employer': float(eis_employer),
            'tax_deduction': float(tax_deduction),
            'other_deductions': float(other_deductions),
            'total_deductions': float(total_deductions),
            'net_salary': float(net_salary),
            'is_malaysian': is_malaysian,
            'individual_adjustments': {
                'bonus': float(individual_bonus),
                'overtime': float(individual_overtime),
                'other_deductions': float(individual_other_deductions)
            },
            'adjustments_count': len(adjustments)
        }
        
    except Exception as e:
        print(f"Error in calculate_monthly_payroll for {employee.full_name}: {str(e)}")
        import traceback
        traceback.print_exc()
        # Return basic structure on error
        return {
            'basic_salary': 0,
            'overtime_hours': 0,
            'overtime_pay': 0,
            'bonuses': 0,
            'unpaid_leave_deduction': 0,
            'epf_employee': 0,
            'epf_employer': 0,
            'socso_employee': 0,
            'socso_employer': 0,
            'eis_employee': 0,
            'eis_employer': 0,
            'tax_deduction': 0,
            'other_deductions': 0,
            'total_deductions': 0,
            'net_salary': 0,
            'is_malaysian': False,
            'individual_adjustments': {'bonus': 0, 'overtime': 0, 'other_deductions': 0},
            'adjustments_count': 0
        }

def calculate_overtime_hours(employee_id, pay_period):
    """Calculate overtime hours for an employee in a pay period"""
    # Implement your overtime calculation logic here
    # This is a placeholder - you'll need to track overtime in your system
    return Decimal('0')

def calculate_unpaid_leave_deduction(salary, unpaid_days):
    """Calculate unpaid leave deduction based on working days"""
    settings = get_payroll_settings()
    working_days = Decimal(str(settings.get('working_days_per_month', 26)))
    daily_rate = salary / working_days
    return round(daily_rate * Decimal(str(unpaid_days)), 2)

@app.route('/payroll/settings', methods=['GET', 'POST'])
@login_required
def payroll_settings():
    if current_user.user_type != 'admin':
        flash('You do not have permission to access payroll settings.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            settings_data = request.get_json()
            
            # Update or create each setting
            for key, value in settings_data.items():
                # Convert boolean values to 'true'/'false' strings for consistent storage
                if isinstance(value, bool):
                    storage_value = 'true' if value else 'false'
                else:
                    storage_value = str(value)
                
                setting = PayrollSettings.query.filter_by(setting_name=key).first()
                if setting:
                    setting.setting_value = storage_value
                    setting.updated_at = datetime.utcnow()
                    setting.updated_by = current_user.id
                else:
                    setting = PayrollSettings(
                        setting_name=key,
                        setting_value=storage_value,
                        updated_by=current_user.id
                    )
                    db.session.add(setting)
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Payroll settings updated successfully!'})
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Error updating settings: {str(e)}'}), 500
    
    # GET request - return current settings
    settings = PayrollSettings.query.all()
    settings_dict = {s.setting_name: s.setting_value for s in settings}
    
    # Return default settings if none exist
    if not settings_dict:
        settings_dict = get_default_payroll_settings()
        # Save default settings to database
        for key, value in settings_dict.items():
            setting = PayrollSettings(
                setting_name=key,
                setting_value=str(value),
                updated_by=current_user.id
            )
            db.session.add(setting)
        db.session.commit()
    
    return jsonify(settings_dict)

def get_default_payroll_settings():
    """Return default payroll calculation settings"""
    return {
        'include_overtime': 'true',
        'include_bonuses': 'true',
        'include_unpaid_leave': 'true',
        'include_epf': 'true',
        'include_socso': 'true',
        'include_eis': 'true',
        'include_tax': 'true',
        'include_other_deductions': 'true',
        'overtime_rate': '15.00',
        'bonus_amount': '0.00',
        'epf_employee_rate': '11.00',
        'epf_employer_rate': '13.00',
        'socso_employee_low': '0.50',
        'socso_employer_low': '0.70',
        'socso_employee_high': '1.00',
        'socso_employer_high': '1.20',
        'eis_employee_rate': '0.50',
        'eis_employer_rate': '0.70',
        'other_deductions_amount': '0.00',
        'working_days_per_month': '26'
    }

def get_payroll_settings():
    """Get payroll calculation settings from database"""
    settings = PayrollSettings.query.all()
    if not settings:
        return get_default_payroll_settings()
    
    settings_dict = {}
    for setting in settings:
        value = setting.setting_value
        
        # Handle boolean settings
        if setting.setting_name.startswith('include_'):
            settings_dict[setting.setting_name] = value.lower() in ('true', '1', 'yes')
        # Handle numeric settings
        elif any(keyword in setting.setting_name for keyword in ['_rate', '_amount', '_low', '_high', '_days']):
            try:
                settings_dict[setting.setting_name] = float(value)
            except (ValueError, TypeError):
                # Get default value from default settings
                default_settings = get_default_payroll_settings()
                settings_dict[setting.setting_name] = float(default_settings.get(setting.setting_name, 0))
        else:
            settings_dict[setting.setting_name] = value
    
    return settings_dict

def calculate_unpaid_leave_for_period(employee_id, pay_period):
    """Calculate unpaid leave deduction for a specific pay period"""
    # Parse pay period (YYYY-MM)
    year, month = map(int, pay_period.split('-'))
    
    # Get unpaid leave requests for this period
    unpaid_leaves = LeaveRequest.query.filter(
        LeaveRequest.employee_id == employee_id,
        LeaveRequest.leave_type == 'unpaid',
        LeaveRequest.status == 'approved',
        db.extract('year', LeaveRequest.start_date) == year,
        db.extract('month', LeaveRequest.start_date) == month
    ).all()
    
    total_unpaid_days = sum(leave.days_requested for leave in unpaid_leaves)
    
    # Get employee basic salary
    employee = Employee.query.get(employee_id)
    if employee and employee.basic_salary:
        return calculate_unpaid_leave_deduction(employee.basic_salary, total_unpaid_days)
    
    return Decimal('0')

# Statutory calculation helpers (Malaysia)
def calculate_socso_employee(salary):
    """Calculate SOCSO contribution for employee"""
    if salary <= Decimal('5000'):
        return Decimal('0.50')  # Simplified amount
    return Decimal('1.00')

def calculate_socso_employer(salary):
    """Calculate SOCSO contribution for employer"""
    if salary <= Decimal('5000'):
        return Decimal('0.70')  # Simplified amount
    return Decimal('1.20')

def calculate_eis_employee(salary):
    """Calculate EIS contribution for employee"""
    return round(salary * Decimal('0.005'), 2)  # 0.5%

def calculate_eis_employer(salary):
    """Calculate EIS contribution for employer"""
    return round(salary * Decimal('0.007'), 2)  # 0.7%

def calculate_tax_deduction(salary):
    """Simplified tax calculation (implement proper Malaysian tax brackets)"""
    annual_salary = salary * Decimal('12')
    
    if annual_salary <= Decimal('5000'):
        return Decimal('0')
    elif annual_salary <= Decimal('20000'):
        return round((annual_salary - Decimal('5000')) * Decimal('0.01') / Decimal('12'), 2)
    elif annual_salary <= Decimal('35000'):
        return round((Decimal('15000') * Decimal('0.01') + (annual_salary - Decimal('20000')) * Decimal('0.03')) / Decimal('12'), 2)
    else:
        return round((Decimal('15000') * Decimal('0.01') + Decimal('15000') * Decimal('0.03') + (annual_salary - Decimal('35000')) * Decimal('0.06')) / Decimal('12'), 2)

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
            LeaveRequest.id != (request.args.get('request_id') if request.args.get('request_id') else None),
            db.or_(
                db.and_(
                    form.start_date.data >= LeaveRequest.start_date,
                    form.start_date.data <= LeaveRequest.end_date
                ),
                db.and_(
                    form.end_date.data >= LeaveRequest.start_date,
                    form.end_date.data <= LeaveRequest.end_date
                ),
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
      
        # Validate leave days against maximum limits
        is_valid, error_message = validate_leave_days(form.leave_type.data, days_requested)
        
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('request_leave.html', form=form)
        
        # Check if user has sufficient leave balance for paid leave types
        paid_leave_types = ['annual', 'medical', 'maternity', 'compassionate', 'marriage', 'hospitalized', 'socso_mc']
        if form.leave_type.data in paid_leave_types:
            leave_balance = LeaveBalance.query.filter_by(
                employee_id=current_user.id,
                leave_type=form.leave_type.data
            ).first()
            
            if not leave_balance:
                # If no balance record exists, create one with default values
                default_days = 20 if form.leave_type.data == 'annual' else (
                    14 if form.leave_type.data in ['medical', 'socso_mc'] else (
                    90 if form.leave_type.data == 'maternity' else (
                    3 if form.leave_type.data in ['compassionate', 'marriage'] else (
                    60 if form.leave_type.data == 'hospitalized' else 0
                ))))
                
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
    
    # Handle unpaid leave salary deduction
    unpaid_deduction = 0
    deduction_note = ""
    if leave_request.leave_type == 'unpaid':
        employee = Employee.query.get(leave_request.employee_id)
        if employee and employee.basic_salary:
            unpaid_deduction = calculate_unpaid_leave_deduction(
                employee.basic_salary, 
                leave_request.days_requested
            )
            deduction_note = f"\nNote: This unpaid leave will result in a salary deduction of ${unpaid_deduction:.2f}"
            flash(f'Unpaid leave approved. Salary deduction: ${unpaid_deduction:.2f}', 'info')
    
    # Rest of your existing approve_leave code remains the same...
    # [Your existing code for deducting leave balances]
    
    db.session.commit()
    
    # Update email to include deduction information
    subject = f"Your Leave Request Has Been Approved"
    body = f"""
Dear {leave_request.employee.full_name},

Your leave request has been approved by {current_user.full_name}.

Details:
- Leave Type: {leave_request.leave_type.replace('_', ' ').title()}
- Start Date: {leave_request.start_date.strftime('%d-%m-%y')}
- End Date: {leave_request.end_date.strftime('%d-%m-%y')}
- Days: {leave_request.days_requested}
- Reason: {leave_request.reason}
{deduction_note}

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
    
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Employees per page
    search_query = request.args.get('search', '')
    
    # Build query
    query = Employee.query
    
    if search_query:
        query = query.filter(
            db.or_(
                Employee.full_name.ilike(f'%{search_query}%'),
                Employee.employee_id.ilike(f'%{search_query}%'),
                Employee.email.ilike(f'%{search_query}%')
            )
        )
    
    # Get paginated results
    employees = query.order_by(Employee.full_name.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('manage_employees.html',
                         employees=employees,
                         search_query=search_query,
                         page=page,
                         per_page=per_page)

@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.user_type != 'admin':
        flash('You do not have permission to add employees.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = AddEmployeeForm()
    
    if form.validate_on_submit():
        username = form.email.data.split('@')[0]
        
        # Check for duplicates
        if Employee.query.filter_by(username=username).first():
            flash('Username already exists. Please use a different email.', 'danger')
            return render_template('add_employee.html', form=form)
        
        if Employee.query.filter_by(employee_id=form.employee_id.data).first():
            flash('Employee ID already exists. Please use a different ID.', 'danger')
            return render_template('add_employee.html', form=form)
        
        if Employee.query.filter_by(email=form.email.data).first():
            flash('Email address already exists. Please use a different email.', 'danger')
            return render_template('add_employee.html', form=form)
        
        # Capitalize nationality
        nationality = form.nationality.data.strip().title()
        
        temp_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
        
        employee = Employee(
            username=username,
            password=generate_password_hash(temp_password),
            full_name=form.full_name.data,
            email=form.email.data,
            nationality=nationality,
            employee_id=form.employee_id.data,
            user_type=form.user_type.data,
            hire_date=datetime.utcnow().date(),
            # NEW FIELDS
            date_joined=form.date_joined.data,
            basic_salary=form.basic_salary.data
        )
        
        db.session.add(employee)
        db.session.commit()
        
        # Create leave balances with calculated annual leave
        annual_leave_days = calculate_annual_leave_days(form.date_joined.data)
        
        for leave_type in ['annual', 'unpaid', 'maternity', 'compassionate', 'marriage', 'hospitalized', 'socso_mc']:
            if leave_type == 'annual':
                default_days = annual_leave_days
            elif leave_type == 'medical':
                default_days = 14
            elif leave_type == 'maternity':
                default_days = 90
            elif leave_type in ['compassionate', 'marriage']:
                default_days = 3
            elif leave_type == 'hospitalized':
                default_days = 60
            elif leave_type == 'socso_mc':
                default_days = 14
            else:  # unpaid and others
                default_days = 0
            
            balance = LeaveBalance(
                employee_id=employee.id,
                leave_type=leave_type,
                total_days=default_days,
                used_days=0,
                remaining_days=default_days
            )
            db.session.add(balance)
        
        db.session.commit()
        
        # Send email (your existing email code)
        server_url = "https://hercules-hr-system.onrender.com/"
        subject = "Your Hercules HR Account Has Been Created"
        body = f"""
Dear {form.full_name.data},

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
        employees_added = []
        
        for line in lines:
            try:
                data = [item.strip() for item in line.split(',')]
                if len(data) != 7:  # Updated from 5 to 7 fields
                    error_count += 1
                    continue
                
                full_name, email, nationality, employee_id, user_type, date_joined_str, basic_salary_str = data
                
                # Parse date and salary
                try:
                    date_joined = datetime.strptime(date_joined_str, '%Y-%m-%d').date()
                    basic_salary = float(basic_salary_str)
                except ValueError:
                    error_count += 1
                    continue
                
                # Capitalize nationality
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
                    nationality=nationality,
                    employee_id=employee_id,
                    user_type=user_type,
                    hire_date=datetime.utcnow().date(),
                    # NEW FIELDS
                    date_joined=date_joined,
                    basic_salary=basic_salary
                )
                
                db.session.add(employee)
                employees_added.append(employee)
                success_count += 1
                
                # Send email 
                server_url = "https://hercules-hr-system.onrender.com/"
                subject = "Your Hercules HR Account Has Been Created"
                body = f"""
Dear {full_name},

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
            annual_leave_days = calculate_annual_leave_days(employee.date_joined)
            
            for leave_type in ['annual', 'unpaid', 'maternity', 'compassionate', 'marriage', 'hospitalized', 'socso_mc']:
                if leave_type == 'annual':
                    default_days = annual_leave_days
                elif leave_type == 'medical':
                    default_days = 14
                elif leave_type == 'maternity':
                    default_days = 90
                elif leave_type in ['compassionate', 'marriage']:
                    default_days = 3
                elif leave_type == 'hospitalized':
                    default_days = 60
                elif leave_type == 'socso_mc':
                    default_days = 14
                else:  # unpaid and others
                    default_days = 0
                
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
            return render_template('edit_employee.html', form=form, employee=employee, calculate_annual_leave_days=calculate_annual_leave_days)
        
        # Capitalize nationality: first letter uppercase, rest lowercase
        nationality = form.nationality.data.strip().title()
        
        employee.full_name = form.full_name.data
        employee.email = form.email.data
        employee.nationality = nationality
        employee.employee_id = form.employee_id.data
        employee.user_type = form.user_type.data
        # NEW FIELDS
        employee.date_joined = form.date_joined.data
        employee.basic_salary = form.basic_salary.data
        
        # Update annual leave balance if date_joined changed
        if form.date_joined.data != employee.date_joined:
            annual_leave_days = calculate_annual_leave_days(form.date_joined.data)
            annual_balance = LeaveBalance.query.filter_by(
                employee_id=employee.id,
                leave_type='annual'
            ).first()
            
            if annual_balance:
                # Calculate the difference in total days
                days_difference = annual_leave_days - annual_balance.total_days
                
                # Update the balance
                annual_balance.total_days = annual_leave_days
                annual_balance.remaining_days += days_difference
                
                # Create history record
                history = LeaveBalanceHistory(
                    employee_id=employee.id,
                    admin_id=current_user.id,
                    leave_type='annual',
                    old_total=annual_balance.total_days - days_difference,
                    new_total=annual_balance.total_days,
                    old_used=annual_balance.used_days,
                    new_used=annual_balance.used_days,
                    old_remaining=annual_balance.remaining_days - days_difference,
                    new_remaining=annual_balance.remaining_days,
                    comment=f"Annual leave updated due to date joined change: {form.date_joined.data}"
                )
                db.session.add(history)
                flash(f'Annual leave balance updated to {annual_leave_days} days based on new join date.', 'info')
        
        db.session.commit()
        
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('edit_employee.html', form=form, employee=employee, calculate_annual_leave_days=calculate_annual_leave_days)

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
    
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Leave requests per page
    
    # Get filter parameters
    employee_id = request.args.get('employee_id')
    leave_type = request.args.get('leave_type')
    status = request.args.get('status')
    start_date_filter = request.args.get('start_date_filter')
    end_date_filter = request.args.get('end_date_filter')
    days_requested = request.args.get('days_requested')
    reason = request.args.get('reason')
    
    # Build query with explicit join condition
    query = LeaveRequest.query.join(Employee, LeaveRequest.employee_id == Employee.id)  # Specify the exact join condition
    
    # Apply filters
    if employee_id:
        query = query.filter(LeaveRequest.employee_id == employee_id)
    if leave_type:
        query = query.filter(LeaveRequest.leave_type == leave_type)
    if status:
        query = query.filter(LeaveRequest.status == status)
    if start_date_filter:
        query = query.filter(LeaveRequest.start_date >= start_date_filter)
    if end_date_filter:
        query = query.filter(LeaveRequest.start_date <= end_date_filter)
    if days_requested:
        query = query.filter(LeaveRequest.days_requested == days_requested)
    if reason:
        query = query.filter(LeaveRequest.reason.ilike(f'%{reason}%'))
    
    # Get paginated results
    leave_requests_paginated = query.order_by(LeaveRequest.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get all employees for filter dropdown
    employees = Employee.query.order_by(Employee.full_name.asc()).all()
    
    # Prepare data for template
    all_requests_data = []
    for leave_request in leave_requests_paginated.items:
        approver_name = 'N/A'
        if leave_request.approved_by_id:
            approver = Employee.query.get(leave_request.approved_by_id)
            approver_name = approver.full_name if approver else 'N/A'
        
        all_requests_data.append({
            'leave_request': leave_request,
            'employee_name': leave_request.employee.full_name,
            'approver_name': approver_name
        })
    
    return render_template('all_leaves.html',
                         all_requests=leave_requests_paginated,
                         employees=employees,
                         filters=request.args,
                         page=page,
                         per_page=per_page)

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

    # Generate temporary password
    temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

    # Assign hash directly
    employee.password = generate_password_hash(temp_password)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to reset password: {str(e)}", 'danger')
        return redirect(url_for('manage_employees'))

    # Send email after commit
    server_url = "https://hercules-hr-system.onrender.com/"
    subject = "Your Hercules HR Password Has Been Reset"
    body = f"""
Dear {employee.full_name},

Your Hercules HR password has been reset by the administrator.  
Username: {employee.username}  
Temporary Password: {temp_password}  

Please log in here: {server_url}  
and change your password immediately.

Best regards,  
Hercules HR Department
"""

    send_email(employee.email, subject, body)
    flash('Password reset successfully. Email notification sent.', 'success')

    return redirect(url_for('manage_employees'))


@app.route('/manage_leave_balances')
@login_required
def manage_leave_balances():
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to manage leave balances.', 'danger')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Employees per page
    employee_name = request.args.get('employee_name', '')
    employee_id_search = request.args.get('employee_id_search', '')
    
    # Build query
    query = Employee.query
    
    if employee_name:
        query = query.filter(Employee.full_name.ilike(f'%{employee_name}%'))
    
    if employee_id_search:
        query = query.filter(Employee.employee_id.ilike(f'%{employee_id_search}%'))
    
    # Get paginated results
    employees = query.order_by(Employee.full_name.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('manage_leave_balances.html',
                         employees=employees,
                         page=page,
                         per_page=per_page)

@app.route('/edit_leave_balance/<int:employee_id>', methods=['GET', 'POST'])
@login_required
def edit_leave_balance(employee_id):
    if current_user.user_type not in ['admin', 'supervisor']:
        flash('You do not have permission to edit leave balances.', 'danger')
        return redirect(url_for('leaves'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Get or create leave balances for all leave types
    leave_types = ['annual', 'unpaid', 'maternity', 'compassionate', 'marriage', 'hospitalized', 'socso_mc']
    leave_balances = {}
    
    for leave_type in leave_types:
        balance = LeaveBalance.query.filter_by(employee_id=employee_id, leave_type=leave_type).first()
        if not balance:
            # Set default values for new leave types
            default_days = 20 if leave_type == 'annual' else (
                14 if leave_type in ['medical', 'socso_mc'] else (
                90 if leave_type == 'maternity' else (
                3 if leave_type in ['compassionate', 'marriage'] else (
                60 if leave_type == 'hospitalized' else 0
            ))))
            balance = LeaveBalance(
                employee_id=employee_id, 
                leave_type=leave_type, 
                total_days=default_days, 
                used_days=0, 
                remaining_days=default_days
            )
            db.session.add(balance)
        leave_balances[leave_type] = balance
    
    if request.method == 'POST':
        try:
            comment = request.form.get('comment', '').strip()
            
            for leave_type in leave_types:
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

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# Your existing imports and app configuration...
# [Keep all your existing imports and app setup code here]

# REMOVE the top-level db.create_all() block entirely

if __name__ == '__main__':
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    # Check if running in Docker/Production
    is_docker = os.path.exists('/.dockerenv')
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    if is_docker or is_production:
        # ==================== PRODUCTION MODE ====================
        print("=== HR System - Production Mode ===")
        print("Starting Flask Server...")
        print(f"Host: 0.0.0.0, Port: 8888")  # ← CHANGED TO 8888
        print(f"Instance path: {app.instance_path}")
        print(f"Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')}")
        
        # Test database connection and create tables if needed
        try:
            with app.app_context():
                db.engine.connect()
                print("✅ Database connection successful")
                
                # Check if tables already exist before creating
                inspector = db.inspect(db.engine)
                existing_tables = inspector.get_table_names()
                
                if not existing_tables:  # Only create if no tables exist
                    print("Creating database tables...")
                    db.create_all()
                    add_is_admin_column()
                    add_time_tracking_columns()
                    add_leave_balance_tables()
                    print("✅ Database tables created!")
                else:
                    print("✅ Database tables already exist")
                    
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
        
        # Test imports
        try:
            from flask import Flask
            print("✅ Flask import successful")
        except ImportError as e:
            print(f"❌ Flask import failed: {e}")
        
        try:
            app.run(host='0.0.0.0', port=8888, debug=False)  # ← CORRECT
            print("✅ Flask server started successfully")
        except Exception as e:
            print(f"❌ ERROR starting Flask app: {e}")
            import traceback
            traceback.print_exc()
        
    else:
        # ==================== DEVELOPMENT MODE ====================
        # Database creation for development
        with app.app_context():
            # Check if tables already exist before creating
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                print("Creating database tables...")
                db.create_all()
                add_is_admin_column()
                add_time_tracking_columns()
                add_leave_balance_tables()
                print("✅ Database tables created!")
            else:
                print("✅ Database tables already exist")
        
        def get_local_ip():
            # Simplified IP detection - just get the network IP
            network_ip = "127.0.0.1"
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.connect(("8.8.8.8", 80))
                    network_ip = s.getsockname()[0]
            except:
                pass  # Keep 127.0.0.1 if detection fails
            
            return network_ip
        
        network_ip = get_local_ip()
        
        print("=" * 50)
        print("HR System - Development Mode")
        print(f"Local:    http://127.0.0.1:8888")  # ← CHANGED TO 8888
        print(f"Network:  http://{network_ip}:8888")  # ← CHANGED TO 8888
        print("=" * 50)
        
        # Run in development mode
        app.run(debug=True, host='0.0.0.0', port=8888)  # ← CHANGED TO 8888

# ==================== GUNICORN COMPATIBILITY ====================
else:
    # This block runs when the app is imported by Gunicorn
    # Ensure instance folder exists
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
        print("✅ Gunicorn: Created instance directory")
    
    # Initialize database connection but don't create tables
    # Tables should already exist from the main process
    with app.app_context():
        try:
            # Test database connection
            db.engine.connect()
            print("✅ Gunicorn: Database connection successful")
            
            # Just verify tables exist without creating them
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if existing_tables:
                print(f"✅ Gunicorn: Found {len(existing_tables)} database tables")
            else:
                print("⚠️ Gunicorn: No database tables found (this might be expected for first run)")
                
        except Exception as e:
            print(f"❌ Gunicorn: Database initialization failed: {e}")
            # Don't crash - let the worker continue and hope main process creates tables
