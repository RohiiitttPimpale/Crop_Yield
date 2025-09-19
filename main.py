from flask import Flask, render_template, request, redirect, url_for, flash
import joblib
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, Float, String
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
import os


class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db.init_app(app=app)
app.secret_key = os.environ.get("FLASK_KEY") # Add secret key for flash messages

login_manager = LoginManager()
login_manager.init_app(app=app)

@login_manager.user_loader
def user_load(user_id):
    return db.get_or_404(User, user_id)

with app.app_context():
    db.create_all()

# Load models with error handling
try:
    if os.path.exists("model/rice_model.pkl") and os.path.exists("model/pipeline.pkl"):
        model = joblib.load("model/rice_model.pkl")
        pipeline = joblib.load("model/pipeline.pkl")
        print("✅ Models loaded successfully")
    else:
        model = None
        pipeline = None
        print("❌ Model files not found. Yield prediction will not work.")
except Exception as e:
    model = None
    pipeline = None
    print(f"❌ Error loading models: {e}")

# Landing page route
@app.route("/")
def home():
    return render_template("landing-page.html")

# Login page route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        print(f"Email: {email}, Password: {password}")  # Debug
        # Simple authentication (replace with real authentication)
        if user:  # Basic validation
            if user.password == password:
                login_user(user)
                return redirect(url_for("dashboard"))
            else:
                flash("Password is incorrect")
        else:
            flash("This Email don't exist, please try another email or do register")
    return render_template("login-page.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Simple authentication (replace with real authentication)
        if email and password and name and confirm_password:
            if password == confirm_password:# Basic validation
                user = User(
                    name=name,
                    email=email,
                    password=password
                )
                db.session.add(user)
                db.session.commit()
                flash("register successful!", "success")
                login_user(user)
                return redirect(url_for("dashboard"))
            else:
                flash("The Password and Confirm password is not same", "error")
        else:
            flash("Please enter both email and password.", "error")
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Dashboard route
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("main-dashboard.html")

# Farmer profile route
@app.route("/farmer-profile")
@login_required
def farmer_profile():
    return render_template("farmer-profile.html")

# Weather dashboard route
@app.route("/weather")
@login_required
def weather():
    return render_template("weather-dashboard.html")

# Crop planning route
@app.route("/crop-planning")
@login_required
def crop_planning():
    return render_template("crop-planning.html")

# Yield predictor route - IMPROVED
@app.route("/yield-predictor", methods=["GET", "POST"])
@login_required
def yield_predictor():
    produce_yield = 0
    error_message = ""

    if request.method == "POST":
        try:
            # Check if models are loaded
            if model is None or pipeline is None:
                error_message = "AI models not available. Please contact administrator."
                return render_template("yield-predictor.html", produce=0, error=error_message)

            # Get form data with validation
            crop = request.form.get("crop")
            area = request.form.get("area")
            ph = request.form.get("ph")
            rainfall = request.form.get("rainfall")
            temper = request.form.get("temper")

            # Validate required fields
            if not all([crop, area, ph, rainfall, temper]):
                error_message = "Please fill in all required fields."
                return render_template("yield-predictor.html", produce=0, error=error_message)

            # Convert to float with error handling
            try:
                area_float = float(area)
                ph_float = float(ph)
                rainfall_float = float(rainfall)
                temper_float = float(temper)
            except ValueError:
                error_message = "Please enter valid numeric values."
                return render_template("yield-predictor.html", produce=0, error=error_message)

            # Validate ranges
            if not (4.0 <= ph_float <= 9.0):
                error_message = "pH value should be between 4.0 and 9.0"
                return render_template("yield-predictor.html", produce=0, error=error_message)

            if rainfall_float < 0:
                error_message = "Rainfall cannot be negative"
                return render_template("yield-predictor.html", produce=0, error=error_message)

            if area_float <= 0:
                error_message = "Area must be greater than 0"
                return render_template("yield-predictor.html", produce=0, error=error_message)

            # Prepare data for model (your existing format)
            data = [["Sundargarh",ph_float, 0.6, rainfall_float,69.45,temper_float,39.1,16.3,35,35]]

            # Transform and predict
            data_transformed = pipeline.transform(data)
            prediction = model.predict(data_transformed)[0]

            row_space_ft = data[0][-2]/30.48
            column_space_ft = data[0][-1]/30.48

            plants_per_acre =(43560)/(row_space_ft*column_space_ft)
            prediction_per_acre_ton = plants_per_acre * prediction/1000000

            # Calculate total yield (prediction per acre * total area)
            produce_yield = prediction_per_acre_ton * area_float

            # Ensure positive result
            if produce_yield < 0:
                produce_yield = 0
                error_message = "Prediction resulted in negative yield. Please check your input values."

            print(f"✅ Prediction successful: {produce_yield:.2f} tons")
            flash(f"AI Prediction Generated: {produce_yield:.2f} tons expected yield", "success")

        except Exception as e:
            error_message = f"Error generating prediction: {str(e)}"
            print(f"❌ Prediction error: {e}")
            produce_yield = 0

    return render_template("yield-predictor.html", produce=produce_yield, error=error_message)

# AI Predictions route (alias for yield predictor)
@app.route("/predictions")
@login_required
def predictions():
    return redirect(url_for("yield_predictor"))

# Yield Records route (placeholder)
@app.route("/yield-records")
@login_required
def yield_records():
    return render_template("main-dashboard.html")

# Recommendations route (placeholder)
@app.route("/recommendations")
@login_required
def recommendations():
    return render_template("main-dashboard.html")

# Reports route (placeholder)
@app.route("/reports")
@login_required
def reports():
    return render_template("main-dashboard.html")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run()