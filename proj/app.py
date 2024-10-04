from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import requests
import os
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import google.generativeai as genai
from time import sleep
import asyncio

load_dotenv()

app = Flask(__name__)

DB_USERNAME = os.getenv('DB_USERNAME')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_FROM_EMAIL = os.getenv('SENDGRID_FROM_EMAIL')

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{
    DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'ThisIsTopLevelSecret'  # Change in production

# Global Forest Watch API configuration
GFW_API_KEY = os.environ['GFW_API_KEY']
GFW_API_BASE_URL = 'https://data-api.globalforestwatch.org/dataset/gfw_integrated_alerts'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
scheduler = BackgroundScheduler()

# Database Models


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_no = db.Column(db.String(15), nullable=False)
    gender = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    progress = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_del = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)


class Tree(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    species = db.Column(db.String(100))
    planting_date = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.user_id'), nullable=False)


class DeforestationAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    alert_date = db.Column(db.DateTime, nullable=False)
    confidence = db.Column(db.String(50))
    alert_type = db.Column(db.String(50))
    gfw_id = db.Column(db.String(100), unique=True)


class OTP(db.Model):
    __tablename__ = 'otps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Temporary storage for registration data
temporary_storage = {}
reset_storage = {}  # Temporary storage for password reset requests

# GFW API Integration


def fetch_gfw_alerts():
    headers = {
        'Authorization': f'Bearer {GFW_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Get alerts for the last 30 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    params = {
        'start_date': start_date.strftime('%Y-%m-%d'),
        'end_date': end_date.strftime('%Y-%m-%d'),
        'format': 'json'
    }

    try:
        response = requests.get(
            f'{GFW_API_BASE_URL}/latest', headers=headers, params=params)
        response.raise_for_status()
        print("Fetched GFW Alerts:", response.json())  # Log the fetched alerts
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching GFW data: {e}")
        return None


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp):
    message = Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email,
        subject='Your OTP for verification',
        html_content=f'<p>Your OTP is: <strong>{
            otp}</strong>. Valid for 10 minutes.</p>'
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        return True
    except Exception as e:
        print(e)
        return False


def process_gfw_alerts(alerts_data):
    if not alerts_data:
        return

    for alert in alerts_data.get('data', []):
        print("Processing alert:", alert)  # Log each alert being processed
        if not DeforestationAlert.query.filter_by(gfw_id=alert['id']).first():
            new_alert = DeforestationAlert(
                latitude=alert['attributes']['latitude'],
                longitude=alert['attributes']['longitude'],
                alert_date=datetime.strptime(
                    alert['attributes']['date'], '%Y-%m-%d'),
                confidence=alert['attributes'].get('confidence', 'unknown'),
                alert_type=alert['attributes'].get('alert_type', 'unknown'),
                gfw_id=alert['id']
            )
            db.session.add(new_alert)

    db.session.commit()


# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['first_name', 'last_name', 'email',
                       'phone_no', 'gender', 'user_name', 'password']

    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    if User.query.filter_by(user_name=data['user_name']).first():
        return jsonify({'error': 'Username already taken'}), 400

    # Hash the password
    hashed_password = generate_password_hash(data['password'])

    # Store registration data temporarily
    otp = generate_otp()
    temporary_storage[data['email']] = {
        'first_name': data['first_name'],
        'last_name': data['last_name'],
        'email': data['email'],
        'phone_no': data['phone_no'],
        'gender': data['gender'],
        'user_name': data['user_name'],
        'password': hashed_password,
        'otp': otp
    }

    # Send OTP email
    if send_otp_email(data['email'], otp):
        return jsonify({'message': 'Registration initiated. Please verify your email.'}), 201
    else:
        return jsonify({'error': 'Failed to send OTP'}), 500


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if email not in temporary_storage:
        return jsonify({'error': 'No registration request found for this email'}), 404

    stored_data = temporary_storage[email]

    if stored_data['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    # Move data from temporary storage to the database
    new_user = User(
        first_name=stored_data['first_name'],
        last_name=stored_data['last_name'],
        email=stored_data['email'],
        phone_no=stored_data['phone_no'],
        gender=stored_data['gender'],
        user_name=stored_data['user_name'],
        password=stored_data['password'],
        progress=0,
        is_verified=True  # Set is_verified to True here
    )

    # Add new user to the database
    try:
        db.session.add(new_user)
        db.session.commit()
        del temporary_storage[email]  # Remove the data from temporary storage
        return jsonify({'message': 'Email verified successfully and registration completed.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username_or_email = data.get('username_or_email')
    password = data.get('password')

    user = User.query.filter(
        (User.email == username_or_email) | (
            User.user_name == username_or_email)
    ).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_del:
        return jsonify({'error': 'This account has been deleted. Please contact support for assistance.'}), 403

    if not user.is_active:
        return jsonify({'error': 'This account is not active. Please contact our support team.'}), 403

    if not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user.is_verified:
        return jsonify({'error': 'Please verify your email first'}), 403

    return jsonify({
        'message': 'Login successful',
        'user': {
            'user_id': user.user_id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'user_name': user.user_name
        }
    }), 200


@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.json
    email = data.get('email')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'Email not found'}), 404

    otp = generate_otp()
    reset_storage[email] = {
        'otp': otp,
        'created_at': datetime.utcnow()
    }

    if send_otp_email(email, otp):
        return jsonify({'message': 'OTP sent to your email for password reset.'}), 200
    else:
        return jsonify({'error': 'Failed to send OTP'}), 500


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    # Validate new password and confirmation
    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    if email not in reset_storage:
        return jsonify({'error': 'No password reset request found for this email'}), 404

    stored_data = reset_storage[email]

    if datetime.utcnow() - stored_data['created_at'] > timedelta(minutes=10):
        del reset_storage[email]  # Remove expired request
        return jsonify({'error': 'OTP expired'}), 400

    if stored_data['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    # Update user password
    user = User.query.filter_by(email=email).first()
    hashed_password = generate_password_hash(new_password)
    user.password = hashed_password
    db.session.commit()

    del reset_storage[email]  # Remove the data from temporary storage

    return jsonify({'message': 'Password has been reset successfully.'}), 200


@app.route('/deforestation-alerts', methods=['GET'])
def get_deforestation_alerts():
    # Parameters for filtering
    days = request.args.get('days', 30, type=int)
    lat = request.args.get('latitude', type=float)
    lon = request.args.get('longitude', type=float)
    radius = request.args.get('radius', 50, type=float)  # radius in kilometers

    print(f"Querying alerts for Latitude: {lat}, Longitude: {
          lon}, Days: {days}, Radius: {radius}")  # Debugging output

    query = DeforestationAlert.query

    if lat and lon:
        query = query.filter(
            db.and_(
                DeforestationAlert.latitude.between(
                    lat - radius / 111, lat + radius / 111),
                DeforestationAlert.longitude.between(
                    lon - radius / 111, lon + radius / 111)
            )
        )

    alerts = query.filter(
        DeforestationAlert.alert_date >= datetime.now() - timedelta(days=days)
    ).order_by(DeforestationAlert.alert_date.desc()).all()

    if not alerts:
        return jsonify({
            "message": "No alerts found in this region."
        }), 404  # Adjust status code if needed

    return jsonify({
        "alerts": [{
            "id": alert.id,
            "latitude": alert.latitude,
            "longitude": alert.longitude,
            "alert_date": alert.alert_date.isoformat(),
            "confidence": alert.confidence,
            "alert_type": alert.alert_type
        } for alert in alerts]
    })


@app.route('/statistics', methods=['GET'])
def get_statistics():
    total_trees = Tree.query.count()
    total_users = User.query.count()
    recent_alerts = DeforestationAlert.query.filter(
        DeforestationAlert.alert_date >= datetime.now() - timedelta(days=30)
    ).count()

    # Calculate the area affected by deforestation
    # This is a simplified calculation
    # Assuming each alert represents 0.1 hectares
    affected_area = recent_alerts * 0.1

    return jsonify({
        "total_trees_planted": total_trees,
        "active_users": total_users,
        "deforestation_alerts_30d": recent_alerts,
        "affected_area_hectares": round(affected_area, 2)
    })


def update_progress(user_name: str):
    with app.app_context():
        User.query.filter_by(user_name=user_name).first().progress += 1
        db.session.commit()

@app.route('/upload', methods=['POST'])
def upload():
    if request.method != 'POST':
        return jsonify({"error": "Invalid method."}), 405

    if 'file' not in request.files:
        return jsonify({"error": "Missing required field: file"}), 400

    for field in ['user_name', 'password']:
        if field not in request.form:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    if os.path.splitext(request.files['file'].filename)[1].casefold() not in ['.png', '.jpg', '.jpeg']:
        return jsonify({"error": "Unsupported file type."}), 406

    # I love LINQ from C#!
    user = User.query.filter_by(user_name=request.form['user_name']).first()
    if user is None or not check_password_hash(user.password, request.form['password']):
        return jsonify({"error": "Invalid username/password."}), 404

    scheduler.add_job(update_progress, 'date', run_date=datetime.now() +
                      timedelta(seconds=1), args=[user.user_name])

    return jsonify({"message": "Image uploaded successfully."}), 200


def setup_scheduler():
    scheduler.add_job(
        func=lambda: process_gfw_alerts(fetch_gfw_alerts()),
        trigger="interval",
        hours=24
    )
    scheduler.start()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        setup_scheduler()
    app.run(debug=True)
