from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session, Response
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime, timedelta
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
import json
import csv
import io
import time
import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
from functools import wraps

# Initialize logging at the top
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallbacksecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Use PostgreSQL DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define SQLAlchemy models
class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    address = db.Column(db.String)
    service = db.Column(db.String, nullable=False)
    details = db.Column(db.String)
    attachments = db.Column(db.String)
    status = db.Column(db.String, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class NewsletterSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    rating = db.Column(db.Integer)
    comment = db.Column(db.String, nullable=False)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    subject = db.Column(db.String)
    message = db.Column(db.String, nullable=False)
    status = db.Column(db.String, default='unread')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BusinessStat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stat_name = db.Column(db.String, unique=True, nullable=False)
    stat_value = db.Column(db.Integer, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin2FA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secret_key = db.Column(db.String, nullable=False)
    is_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
        # Initialize default stats if not present
        default_stats = [
            ('jobs_completed', 0),
            ('customer_satisfaction', 0),
            ('monthly_bookings', 0),
            ('areas_served', 0),
            ('years_experience', 0),
            ('newsletter_subscribers', 0)
        ]
        for stat_name, stat_value in default_stats:
            if not BusinessStat.query.filter_by(stat_name=stat_name).first():
                stat = BusinessStat(stat_name=stat_name, stat_value=stat_value)
                db.session.add(stat)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")

app.permanent_session_lifetime = timedelta(hours=2)
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", EMAIL_ADDRESS)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD"))

if not ADMIN_USERNAME or not os.getenv("ADMIN_PASSWORD"):
    raise ValueError("ADMIN_USERNAME and ADMIN_PASSWORD must be set in environment variables")

login_attempts = {}
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 900

UPLOAD_FOLDER = 'Uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to_email, subject, body, attachments=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        if attachments:
            for file_path in attachments:
                if os.path.exists(file_path):
                    with open(file_path, "rb") as attachment:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(attachment.read())
                    
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {os.path.basename(file_path)}'
                    )
                    msg.attach(part)
        
        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False

def update_stat(stat_name, increment=1):
    stat = BusinessStat.query.filter_by(stat_name=stat_name).first()
    if stat:
        stat.stat_value += increment
        stat.updated_at = datetime.utcnow()
        db.session.commit()

@app.before_request
def make_session_permanent():
    session.permanent = True
    
    if 'admin_logged_in' in session:
        last_activity = session.get('last_activity')
        session_duration = session.get('session_duration', 'regular')
        
        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            time_diff = datetime.now() - last_activity_time
            
            timeout = timedelta(days=30) if session_duration == 'remember_me' else timedelta(hours=2)
            
            if time_diff > timeout:
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('admin_login'))
        
        session['last_activity'] = datetime.now().isoformat()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact', methods=['POST'])
def contact():
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        service = request.form.get('service', '').strip()
        details = request.form.get('details', '').strip()
        
        if not all([name, email, phone, service]):
            return jsonify({'success': False, 'message': 'Please fill in all required fields.'}), 400
        
        uploaded_files = []
        attachment_names = []
        if 'attachment' in request.files:
            files = request.files.getlist('attachment')
            for file in files:
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
                    filename = timestamp + filename
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    uploaded_files.append(filepath)
                    attachment_names.append(filename)
        
        quote = Quote(
            name=name,
            email=email,
            phone=phone,
            address=address,
            service=service,
            details=details,
            attachments=json.dumps(attachment_names)
        )
        db.session.add(quote)
        db.session.commit()
        quote_id = quote.id
        
        admin_subject = f"🏠 New Quote Request from {name} (#{quote_id})"
        admin_body = f"""
New quote request received from SL Cleaning website:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 QUOTE REQUEST #{quote_id}

📋 CUSTOMER DETAILS:
Name: {name}
Email: {email}
Phone: {phone}
Address: {address if address else 'Not provided'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧽 SERVICE REQUESTED:
{service}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📝 ADDITIONAL DETAILS:
{details if details else 'No additional details provided'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 ATTACHMENTS: {len(uploaded_files)} file(s) attached

⏰ SUBMITTED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

View in admin panel: /admin/quotes

Please respond to this customer within 2 hours as promised.
Customer email: {email}
Customer phone: {phone}
"""
        
        admin_success = send_email(ADMIN_EMAIL, admin_subject, admin_body, uploaded_files)
        
        customer_subject = "🎉 Quote Request Received - SL Cleaning & Laundry"
        customer_body = f"""
Dear {name},

Thank you for your interest in SL Cleaning & Laundry Services!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ YOUR REQUEST HAS BEEN RECEIVED (Reference: #{quote_id})

We have received your quote request for: {service}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⏰ WHAT HAPPENS NEXT:

1. 📞 We will contact you within 2 hours during business hours
2. 💬 We'll discuss your specific requirements
3. 📋 Provide you with a detailed, free quote
4. 📅 Schedule your cleaning service at your convenience

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📞 CONTACT INFORMATION:
Phone: +44 7479 691603
Email: Your reply will reach us directly
Address: 29 South Street, Reading RG1 4QU
Hours: Monday-Sunday, 09:00-17:00

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💰 SPECIAL OFFER: Don't forget to mention discount code "WELCOME10" for 10% off your first service!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Thank you for choosing SL Cleaning & Laundry Services.
We look forward to creating a spotless environment for you!

Best regards,
The SL Cleaning & Laundry Services Team
"""
        
        customer_success = send_email(email, customer_subject, customer_body)
        
        for filepath in uploaded_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                logger.error(f"Failed to delete file {filepath}: {e}")
        
        update_stat('monthly_bookings', 1)
        
        logger.info(f"New quote request from {name} ({email}) for {service} - Quote #{quote_id}")
        
        if admin_success:
            return jsonify({
                'success': True,
                'message': f'Thank you! Your quote request (#{quote_id}) has been submitted successfully. We will contact you within 2 hours during business hours.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'There was an error submitting your request. Please try calling us directly at +44 7479 691603.'
            }), 500
    except Exception as e:
        logger.error(f"Contact form error: {e}")
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred. Please try again or contact us directly.'
        }), 500

@app.route('/newsletter', methods=['POST'])
def newsletter():
    try:
        email = request.form.get('email', '').strip()
        
        if not email:
            return jsonify({'success': False, 'message': 'Please provide a valid email address.'}), 400
        
        try:
            subscription = NewsletterSubscription(email=email)
            db.session.add(subscription)
            db.session.commit()
            update_stat('newsletter_subscribers', 1)
        except db.exc.IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'This email is already subscribed to our newsletter.'}), 400
        
        email_subject = '🎉 Welcome to SL Cleaning & Laundry - Your 10% Discount Inside!'
        email_body = f"""\
Subject: {email_subject}

Welcome to SL Cleaning & Laundry Services!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎉 YOUR EXCLUSIVE 10% DISCOUNT CODE 🎉

💰 DISCOUNT CODE: WELCOME10

This code is valid for your first service booking with us!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧽 HOW TO USE YOUR DISCOUNT:

1. 📞 Call us at +44 7479 691603
2. 🌐 Request a quote at https://slcleaninglaundry.co.uk
3. 💬 Mention discount code "WELCOME10"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📧 WHAT YOU'LL RECEIVE IN OUR NEWSLETTER:

✨ Professional cleaning tips and tricks
💰 Exclusive special offers and discounts
📅 Seasonal cleaning reminders
🆕 New service announcements
🎯 Expert advice for spotless spaces

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🏢 ABOUT SL CLEANING & LAUNDRY SERVICES:

📍 Location: 29 South Street, Reading RG1 4QU
📞 Phone: +44 7479 691603
🌐 Website: https://slcleaninglaundry.co.uk
📅 Available: Monday-Sunday, 09:00-17:00

We specialize in:
• Residential & Commercial Cleaning
• Professional Laundry Services
• Deep Cleaning & Maintenance
• Specialized Cleaning Solutions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌟 WHY CHOOSE US?

✅ Constant communication until job completion
✅ Free quotes with transparent pricing
✅ Professional, experienced team
✅ 7 days a week availability
✅ Local to Reading - we understand your needs
✅ Commitment to spotless results

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ready to experience professional cleaning services?
Get your free quote today and save 10% on your first service!

Best regards,
The SL Cleaning & Laundry Services Team

Creating spotless environments across Reading, UK
"""
        
        if send_email(email, email_subject, email_body):
            logger.info(f"Newsletter subscription: {email}")
            return jsonify({
                'success': True,
                'message': 'Thank you for subscribing! Check your email for your 10% discount code.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send confirmation email. Please try again.'
            }), 500
            
    except Exception as e:
        logger.error(f"Newsletter subscription error: {e}")
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500

@app.route('/comments', methods=['POST'])
def add_comment():
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '').strip()
        
        if not all([name, email, rating, comment]):
            return jsonify({'success': False, 'message': 'Please fill in all fields.'}), 400
        
        if rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5.'}), 400
        
        new_comment = Comment(name=name, email=email, rating=rating, comment=comment)
        db.session.add(new_comment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your review! It will be published after approval.'
        })
        
    except Exception as e:
        logger.error(f"Comment submission error: {e}")
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500

@app.route('/api/comments')
def get_comments():
    comments = Comment.query.filter_by(approved=True).order_by(Comment.created_at.desc()).limit(10).all()
    return jsonify([{
        'name': comment.name,
        'rating': comment.rating,
        'comment': comment.comment,
        'date': comment.created_at.isoformat()
    } for comment in comments])

@app.route('/api/stats')
def get_stats():
    try:
        stats = BusinessStat.query.all()
        return jsonify({stat.stat_name: stat.stat_value for stat in stats})
    except Exception as e:
        logger.error(f"Error in /api/stats: {e}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/performance_data')
@login_required
def get_performance_data():
    period = request.args.get('period', 'monthly')
    
    if period == 'daily':
        query = db.session.query(
            db.func.to_char(Quote.created_at, 'YYYY-MM-DD').label('period'),
            db.func.count().label('bookings'),
            db.func.sum(db.case((Quote.status == 'completed', 1), else_=0)).label('jobs_completed')
        ).filter(Quote.created_at >= db.func.now() - timedelta(days=30)).group_by(db.func.to_char(Quote.created_at, 'YYYY-MM-DD')).order_by('period')
    elif period == 'weekly':
        query = db.session.query(
            db.func.to_char(Quote.created_at, 'IYYY-IW').label('period'),  # ISO week
            db.func.count().label('bookings'),
            db.func.sum(db.case((Quote.status == 'completed', 1), else_=0)).label('jobs_completed')
        ).filter(Quote.created_at >= db.func.now() - timedelta(weeks=12)).group_by(db.func.to_char(Quote.created_at, 'IYYY-IW')).order_by('period')
    elif period == '90':
        query = db.session.query(
            db.func.to_char(Quote.created_at, 'YYYY-MM-DD').label('period'),
            db.func.count().label('bookings'),
            db.func.sum(db.case((Quote.status == 'completed', 1), else_=0)).label('jobs_completed')
        ).filter(Quote.created_at >= db.func.now() - timedelta(days=90)).group_by(db.func.to_char(Quote.created_at, 'YYYY-MM-DD')).order_by('period')
    elif period == '365':
        query = db.session.query(
            db.func.to_char(Quote.created_at, 'YYYY-MM').label('period'),
            db.func.count().label('bookings'),
            db.func.sum(db.case((Quote.status == 'completed', 1), else_=0)).label('jobs_completed')
        ).filter(Quote.created_at >= db.func.now() - timedelta(days=365)).group_by(db.func.to_char(Quote.created_at, 'YYYY-MM')).order_by('period')
    else:
        query = db.session.query(
            db.func.to_char(Quote.created_at, 'YYYY-MM').label('period'),
            db.func.count().label('bookings'),
            db.func.sum(db.case((Quote.status == 'completed', 1), else_=0)).label('jobs_completed')
        ).filter(Quote.created_at >= db.func.now() - timedelta(days=180)).group_by(db.func.to_char(Quote.created_at, 'YYYY-MM')).order_by('period')

    performance_data = query.all()
    
    labels = [row.period for row in performance_data]
    bookings = [row.bookings for row in performance_data]
    jobs_completed = [row.jobs_completed for row in performance_data]

    return jsonify({
        'labels': labels,
        'bookings': bookings,
        'jobs_completed': jobs_completed
    })

@app.route('/api/service_distribution')
@login_required
def get_service_distribution():
    try:
        service_data = db.session.query(
            Quote.service,
            db.func.count().label('count')
        ).filter(
            db.func.to_char(Quote.created_at, 'YYYY-MM') == db.func.to_char(db.func.now(), 'YYYY-MM')
        ).group_by(Quote.service).all()
        
        labels = [row.service for row in service_data]
        counts = [row.count for row in service_data]
        
        return jsonify({
            'labels': labels,
            'data': counts
        })
    except Exception as e:
        logger.error(f"Error in /api/service_distribution: {e}")
        return jsonify({'error': 'Failed to fetch service data'}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    
    current_time = time.time()
    if client_ip in login_attempts:
        attempts = login_attempts[client_ip]
        attempts = [attempt_time for attempt_time in attempts if current_time - attempt_time < RATE_LIMIT_WINDOW]
        login_attempts[client_ip] = attempts
        
        if len(attempts) >= RATE_LIMIT_ATTEMPTS:
            flash(f'Too many login attempts. Please try again in {RATE_LIMIT_WINDOW // 60} minutes.', 'danger')
            return render_template('admin_login.html')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            if client_ip in login_attempts:
                del login_attempts[client_ip]
            
            session.clear()
            session['admin_logged_in'] = True
            session['last_activity'] = datetime.now().isoformat()
            
            if remember_me:
                session['session_duration'] = 'remember_me'
            else:
                session['session_duration'] = 'regular'
            
            admin_2fa = Admin2FA.query.filter_by(id=1).first()
            if admin_2fa and admin_2fa.is_enabled:
                session['temp_admin_login'] = True
                return redirect(url_for('verify_2fa'))
            
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            if client_ip not in login_attempts:
                login_attempts[client_ip] = []
            login_attempts[client_ip].append(current_time)
            
            remaining_attempts = RATE_LIMIT_ATTEMPTS - len(login_attempts[client_ip])
            flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_admin_login' not in session:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        backup_code = request.form.get('backup_code')
        
        admin_2fa = Admin2FA.query.filter_by(id=1).first()
        
        if admin_2fa:
            verified = False
            
            if token:
                totp = pyotp.TOTP(admin_2fa.secret_key)
                verified = totp.verify(token)
            
            elif backup_code:
                backup_codes = json.loads(admin_2fa.backup_codes or '[]')
                if backup_code.upper() in backup_codes:
                    backup_codes.remove(backup_code.upper())
                    admin_2fa.backup_codes = json.dumps(backup_codes)
                    db.session.commit()
                    verified = True
            
            if verified:
                session.pop('temp_admin_login', None)
                session['admin_logged_in'] = True
                session['last_activity'] = datetime.now().isoformat()
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
        
        flash('Invalid token or backup code.', 'danger')
    
    return render_template('admin_2fa_verify.html')

@app.route('/admin/setup-2fa')
@login_required
def setup_2fa():
    existing_2fa = Admin2FA.query.filter_by(id=1).first()
    
    if not existing_2fa:
        secret = pyotp.random_base32()
        new_2fa = Admin2FA(id=1, secret_key=secret)
        db.session.add(new_2fa)
        db.session.commit()
    else:
        secret = existing_2fa.secret_key
    
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=ADMIN_USERNAME,
        issuer_name="SL Cleaning Admin"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('admin_2fa_setup.html', 
                         secret=secret, 
                         qr_code=qr_code_data)

@app.route('/admin/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    token = request.form.get('token')
    
    admin_2fa = Admin2FA.query.filter_by(id=1).first()
    
    if admin_2fa:
        totp = pyotp.TOTP(admin_2fa.secret_key)
        if totp.verify(token):
            backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
            admin_2fa.is_enabled = True
            admin_2fa.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            
            flash('2FA enabled successfully! Save your backup codes.', 'success')
            return render_template('admin_2fa_backup_codes.html', backup_codes=backup_codes)
        else:
            flash('Invalid token. Please try again.', 'danger')
            return redirect(url_for('setup_2fa'))
    
    flash('2FA setup error.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    stats = BusinessStat.query.all()
    stats_dict = {stat.stat_name: stat.stat_value for stat in stats}
    
    quotes = Quote.query.order_by(Quote.created_at.desc()).limit(10).all()
    quotes_with_dates = [(quote, quote.created_at.strftime('%Y-%m-%d %H:%M:%S') if quote.created_at else 'N/A') for quote in quotes]
    
    pending_comments = Comment.query.filter_by(approved=False).order_by(Comment.created_at.desc()).all()
    
    newsletter_count = NewsletterSubscription.query.filter_by(active=True).count()
    
    return render_template('admin_dashboard.html', 
                         stats=stats_dict,
                         quotes=quotes_with_dates,
                         pending_comments=pending_comments,
                         newsletter_count=newsletter_count)

@app.route('/admin/quotes')
@login_required
def admin_quotes():
    quotes = Quote.query.order_by(Quote.created_at.desc()).all()
    quotes_with_dates = [(quote, quote.created_at.strftime('%Y-%m-%d %H:%M:%S') if quote.created_at else 'N/A') for quote in quotes]
    return render_template('admin_quotes.html', quotes=quotes_with_dates)

@app.route('/admin/quotes/<int:quote_id>/status', methods=['POST'])
@login_required
def update_quote_status(quote_id):
    new_status = request.form.get('status')
    
    quote = Quote.query.get(quote_id)
    if quote:
        quote.status = new_status
        quote.updated_at = datetime.utcnow()
        db.session.commit()
        
        if new_status == 'completed':
            update_stat('jobs_completed', 1)
    
    flash(f'Quote #{quote_id} status updated to {new_status}', 'success')
    return redirect(url_for('admin_quotes'))

@app.route('/admin/quotes/<int:quote_id>/details', methods=['GET'])
@login_required
def get_quote_details(quote_id):
    quote = Quote.query.get(quote_id)
    
    if not quote:
        return jsonify({'success': False, 'message': 'Quote not found'}), 404
    
    return jsonify({
        'success': True,
        'id': quote.id,
        'name': quote.name,
        'email': quote.email,
        'phone': quote.phone,
        'address': quote.address,
        'service': quote.service,
        'details': quote.details,
        'status': quote.status,
        'created_at': quote.created_at.strftime('%Y-%m-%d %H:%M:%S') if quote.created_at else 'N/A',
        'attachments': quote.attachments
    })

@app.route('/api/export/quotes', methods=['GET'])
@login_required
def export_quotes():
    try:
        quotes = Quote.query.order_by(Quote.created_at.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Name', 'Email', 'Phone', 'Address', 'Service', 'Details', 'Status', 'Created At', 'Attachments'])

        for quote in quotes:
            writer.writerow([
                quote.id,
                quote.name,
                quote.email,
                quote.phone,
                quote.address or '',
                quote.service,
                quote.details or '',
                quote.status,
                quote.created_at.isoformat() if quote.created_at else '',
                quote.attachments or ''
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=quotes_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )

    except Exception as e:
        logger.error(f"Export quotes error: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to export quotes data'
        }), 500

@app.route('/api/export/newsletter', methods=['GET'])
@login_required
def export_newsletter():
    try:
        subscribers = NewsletterSubscription.query.order_by(NewsletterSubscription.subscribed_at.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Email', 'Subscribed Date', 'Status'])
        
        for subscriber in subscribers:
            writer.writerow([
                subscriber.email,
                subscriber.subscribed_at.isoformat(),
                'Active' if subscriber.active else 'Inactive'
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=newsletter_subscribers_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )

    except Exception as e:
        logger.error(f"Export newsletter error: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to export newsletter data'
        }), 500

def check_templates():
    required_templates = [
        'admin_dashboard.html',
        'admin_login.html',
        'admin_quotes.html',
        'admin_comments.html',
        'admin_stats.html',
        'admin_newsletter.html',
        'index.html',
        'admin_2fa_setup.html',
        'admin_2fa_verify.html',
        'admin_2fa_backup_codes.html'
    ]
    
    missing_templates = []
    for template in required_templates:
        template_path = os.path.join('templates', template)
        if not os.path.exists(template_path):
            missing_templates.append(template)
    
    if missing_templates:
        logger.warning(f"Missing templates: {missing_templates}")
    
    return missing_templates

@app.route('/admin/comments')
@login_required
def admin_comments():
    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('admin_comments.html', comments=comments)

@app.route('/admin/comments/<int:comment_id>/approve', methods=['POST'])
@login_required
def approve_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if comment:
        comment.approved = True
        db.session.commit()
    
    flash('Comment approved successfully!', 'success')
    return redirect(url_for('admin_comments'))

@app.route('/admin/comments/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if comment:
        db.session.delete(comment)
        db.session.commit()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('admin_comments'))

@app.route('/admin/newsletter')
@login_required
def admin_newsletter():
    subscribers = NewsletterSubscription.query.filter_by(active=True).order_by(NewsletterSubscription.subscribed_at.desc()).all()
    return render_template('admin_newsletter.html', subscribers=subscribers)

@app.route('/admin/stats', methods=['GET', 'POST'])
@login_required
def admin_stats():
    if request.method == 'POST':
        stat_name = request.form.get('stat_name')
        stat_value = request.form.get('stat_value', type=int)
        
        stat = BusinessStat.query.filter_by(stat_name=stat_name).first()
        if stat:
            stat.stat_value = stat_value
            stat.updated_at = datetime.utcnow()
            db.session.commit()
        
        flash('Statistics updated successfully!', 'success')
        return redirect(url_for('admin_stats'))
    
    stats = BusinessStat.query.order_by(BusinessStat.stat_name).all()
    return render_template('admin_stats.html', stats=stats)

@app.route('/admin/quotes/<int:quote_id>/delete', methods=['POST'])
@login_required
def admin_delete_quote(quote_id):
    quote = Quote.query.get(quote_id)
    if quote:
        db.session.delete(quote)
        db.session.commit()
    flash('Quote deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        'success': False,
        'message': 'File too large. Please upload files smaller than 16MB.'
    }), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('index.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({
        'success': False,
        'message': 'Internal server error. Please try again or contact us directly.'
    }), 500

if __name__ == '__main__':
    app.run(debug=True)