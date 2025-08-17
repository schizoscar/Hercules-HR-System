from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

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
    # Add more HR-specific fields as needed

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

# Add this right before your route definitions
with app.app_context():
    db.create_all()
    print("Database tables created!")

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/create_test_user')  # temporary
def create_test_user():
    test_user = Employee(
        username='admin',
        password=generate_password_hash('temp_password'),  # Now hashed!
        full_name='Admin User',
        email='admin@example.com',
        department='IT',
        position='Administrator'
    )
    db.session.add(test_user)
    db.session.commit()
    return "Test user created with hashed password"

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Employee.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):  # Secure check
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
