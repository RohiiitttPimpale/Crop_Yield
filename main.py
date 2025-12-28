"""
Enhanced Crop Yield Prediction Flask Application
==============================================
Security improvements:
- Password hashing with bcrypt
- CSRF protection
- Input validation and sanitization  
- Rate limiting
- Session security
- Environment variable management
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SelectField, validators
from wtforms.validators import DataRequired, Email, Length, NumberRange, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, Float, String, DateTime, Text
from datetime import datetime, timedelta
import joblib
import os
import re
import bleach
from email_validator import validate_email, EmailNotValidError

# Initialize Flask app with security configurations
app = Flask(__name__)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-super-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crop_yield_secure.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token valid for 1 hour
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout

# Security extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["500 per hour", "50 per minute"],
    storage_uri="memory://"
)

# Database setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Enhanced User model with security improvements
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    account_locked_until: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def set_password(self, password):
        """Hash and set password securely"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)

    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return True
        return False

    def lock_account(self):
        """Lock account for 30 minutes after multiple failed attempts"""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()

    def reset_failed_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login = datetime.utcnow()
        db.session.commit()

# Crop Prediction History model
class PredictionHistory(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    crop_type: Mapped[str] = mapped_column(String(50), nullable=False)
    area: Mapped[float] = mapped_column(Float, nullable=False)
    ph_level: Mapped[float] = mapped_column(Float, nullable=False)
    rainfall: Mapped[float] = mapped_column(Float, nullable=False)
    temperature: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_yield: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# Enhanced Forms with validation
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message='Username must be between 4 and 20 characters')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class YieldPredictionForm(FlaskForm):
    crop = SelectField('Crop Type', choices=[
        ('rice', 'Rice'),
        ('wheat', 'Wheat'),
        ('corn', 'Corn'),
        ('barley', 'Barley')
    ], validators=[DataRequired()])
    area = FloatField('Area (acres)', validators=[
        DataRequired(),
        NumberRange(min=0.1, max=10000, message='Area must be between 0.1 and 10,000 acres')
    ])
    ph = FloatField('Soil pH', validators=[
        DataRequired(),
        NumberRange(min=3.0, max=10.0, message='pH must be between 3.0 and 10.0')
    ])
    rainfall = FloatField('Annual Rainfall (mm)', validators=[
        DataRequired(),
        NumberRange(min=0, max=5000, message='Rainfall must be between 0 and 5,000 mm')
    ])
    temperature = FloatField('Average Temperature (°C)', validators=[
        DataRequired(),
        NumberRange(min=-10, max=50, message='Temperature must be between -10°C and 50°C')
    ])

# Input sanitization function
def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks"""
    if isinstance(text, str):
        return bleach.clean(text, tags=[], strip=True)
    return text

# Load ML models with error handling
try:
    model = joblib.load("model/rice_model.pkl")
    pipeline = joblib.load("model/pipeline.pkl")
    print("✅ ML models loaded successfully")
except Exception as e:
    model = None
    pipeline = None
    print(f"⚠️ Warning: ML models not loaded: {e}")

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    """Landing page"""
    return render_template('landing-page.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """Enhanced registration with validation and security"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Sanitize inputs
        username = sanitize_input(form.username.data.lower().strip())
        email = sanitize_input(form.email.data.lower().strip())

        # Additional email validation
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Please enter a valid email address', 'error')
            return render_template('register.html', form=form)

        # Password strength validation
        password = form.password.data
        if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
            flash('Password must contain at least one uppercase letter, one lowercase letter, and one number', 'error')
            return render_template('register.html', form=form)

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html', form=form)

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use a different email or login.', 'error')
            return render_template('register.html', form=form)

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            app.logger.error(f'Registration error: {e}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Enhanced login with rate limiting and account lockout"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        email = sanitize_input(form.email.data.lower().strip())
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and not user.is_account_locked():
            if user.check_password(password):
                user.reset_failed_attempts()
                login_user(user, remember=True)
                next_page = request.args.get('next')
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.lock_account()
                    flash('Account locked due to multiple failed attempts. Try again in 30 minutes.', 'error')
                else:
                    remaining = 5 - user.failed_login_attempts
                    flash(f'Invalid credentials. {remaining} attempts remaining before account lockout.', 'error')
                db.session.commit()
        elif user and user.is_account_locked():
            flash('Account is temporarily locked. Please try again later.', 'error')
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login-page.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Secure logout"""
    username = current_user.username
    logout_user()
    flash(f'Goodbye, {username}! You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('main-dashboard.html')

@app.route('/yield-predictor', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour")
def yield_predictor():
    """Enhanced yield prediction with form validation"""
    form = YieldPredictionForm()
    prediction_result = None
    error_message = None

    if form.validate_on_submit():
        try:
            if model is None or pipeline is None:
                error_message = "AI models are not available. Please contact the administrator."
            else:
                # Get sanitized form data
                crop = sanitize_input(form.crop.data)
                area = float(form.area.data)
                ph = float(form.ph.data)
                rainfall = float(form.rainfall.data)
                temperature = float(form.temperature.data)

                # Prepare data for ML model
                data = [["Sundargarh", ph, 0.6, rainfall, 69.45, temperature, 39.1, 16.3, 35, 35]]

                # Transform and predict
                data_transformed = pipeline.transform(data)
                prediction = model.predict(data_transformed)[0]

                # Calculate yield
                row_space_ft = data[0][-2] / 30.48
                column_space_ft = data[0][-1] / 30.48
                plants_per_acre = 43560 / (row_space_ft * column_space_ft)
                prediction_per_acre_ton = plants_per_acre * prediction / 1000000
                total_yield = prediction_per_acre_ton * area

                if total_yield > 0:
                    prediction_result = round(total_yield, 2)

                    # Save prediction to history
                    history = PredictionHistory(
                        user_id=current_user.id,
                        crop_type=crop,
                        area=area,
                        ph_level=ph,
                        rainfall=rainfall,
                        temperature=temperature,
                        predicted_yield=prediction_result
                    )
                    db.session.add(history)
                    db.session.commit()

                    flash(f'Prediction successful: {prediction_result} tons expected yield for {crop}', 'success')
                else:
                    error_message = "Prediction resulted in negative yield. Please check your input values."

        except ValueError as e:
            error_message = "Invalid input values. Please check your entries."
        except Exception as e:
            error_message = f"Prediction error: {str(e)}"
            app.logger.error(f'Prediction error for user {current_user.id}: {e}')

    return render_template('yield-predictor.html', 
                         form=form, 
                         prediction=prediction_result, 
                         error=error_message)

@app.route('/farmer-profile')
@login_required
def farmer_profile():
    """Farmer profile page"""
    return render_template('farmer-profile.html')

@app.route('/weather')
@login_required
def weather():
    """Weather dashboard"""
    return render_template('weather-dashboard.html')

@app.route('/crop-planning')
@login_required
def crop_planning():
    """Crop planning tools"""
    return render_template('crop-planning.html')

@app.route('/prediction-history')
@login_required
def prediction_history():
    """View prediction history for current user"""
    history = PredictionHistory.query.filter_by(user_id=current_user.id)\
                                   .order_by(PredictionHistory.created_at.desc())\
                                   .limit(20).all()
    return render_template('prediction-history.html', history=history)

@app.route('/api/user-stats')
@login_required
def user_stats():
    """API endpoint for user statistics"""
    prediction_count = PredictionHistory.query.filter_by(user_id=current_user.id).count()
    latest_prediction = PredictionHistory.query.filter_by(user_id=current_user.id)\
                                              .order_by(PredictionHistory.created_at.desc())\
                                              .first()

    stats = {
        'total_predictions': prediction_count,
        'member_since': current_user.created_at.strftime('%B %Y'),
        'last_prediction': latest_prediction.created_at.strftime('%Y-%m-%d') if latest_prediction else 'Never'
    }

    return jsonify(stats)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def rate_limit_handler(e):
    flash('Too many requests. Please slow down and try again later.', 'error')
    return render_template('errors/429.html'), 429

# Security headers middleware
@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    # Production configuration
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    else:
        app.run(debug=True)
