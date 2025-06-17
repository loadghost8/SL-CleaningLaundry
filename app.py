from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session, Response
from datetime import datetime, timedelta
import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
from datetime import datetime
import sqlite3
from functools import wraps
import json
import csv
import io
import time
import pyotp
import qrcode
from io import BytesIO
import base64
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallbacksecretkey')
app.permanent_session_lifetime = timedelta(hours=2)  # Default timeout
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", EMAIL_ADDRESS)

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD"))

# Validate admin credentials
if not ADMIN_USERNAME or not os.getenv("ADMIN_PASSWORD"):
    raise ValueError("ADMIN_USERNAME and ADMIN_PASSWORD must be set in environment variables")

# IP Whitelisting Configuration
ADMIN_IP_WHITELIST = os.getenv("ADMIN_IP_WHITELIST", "").split(",")
ADMIN_IP_WHITELIST = [ip.strip() for ip in ADMIN_IP_WHITELIST if ip.strip()]

# Rate limiting storage
login_attempts = {}
RATE_LIMIT_ATTEMPTS = 5  # Max attempts
RATE_LIMIT_WINDOW = 900  # 15 minutes in seconds

UPLOAD_FOLDER = 'Uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'cleaning_service.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT,
            service TEXT NOT NULL,
            details TEXT,
            attachments TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS newsletter_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            rating INTEGER CHECK(rating >= 1 AND rating <= 5),
            comment TEXT NOT NULL,
            approved BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            status TEXT DEFAULT 'unread',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS business_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stat_name TEXT UNIQUE NOT NULL,
            stat_value INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_2fa (
            id INTEGER PRIMARY KEY,
            secret_key TEXT NOT NULL,
            is_enabled BOOLEAN DEFAULT 0,
            backup_codes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    default_stats = [
        ('jobs_completed', 0),
        ('customer_satisfaction', 0),
        ('monthly_bookings', 0),
        ('areas_served', 0),
        ('years_experience', 0),
        ('newsletter_subscribers', 0)
    ]

    for stat_name, stat_value in default_stats:
        cursor.execute('''
            INSERT OR IGNORE INTO business_stats (stat_name, stat_value)
            VALUES (?, ?)
        ''', (stat_name, stat_value))

    conn.commit()
    conn.close()

def update_quote_status_db(quote_id, new_status):
    """Update quote status in database"""
    conn = get_db_connection()
    conn.execute("UPDATE quotes SET status = ? WHERE id = ?", (new_status, quote_id))
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def ip_whitelist_required(f):
    """Decorator to check IP whitelist for admin routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ADMIN_IP_WHITELIST:
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
            if client_ip not in ADMIN_IP_WHITELIST:
                flash('Access denied from this IP address.', 'danger')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    """Decorator to require admin login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to_email, subject, body, attachments=None):
    """Send email with optional attachments"""
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
    """Update business statistics"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE business_stats 
        SET stat_value = stat_value + ?, updated_at = CURRENT_TIMESTAMP
        WHERE stat_name = ?
    ''', (increment, stat_name))
    conn.commit()
    conn.close()

@app.before_request
def make_session_permanent():
    """Enhanced session management with flexible timeouts"""
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
    """Main page with newsletter subscription"""
    return render_template('index.html')

@app.route('/contact', methods=['POST'])
def contact():
    """Handle contact form submissions"""
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
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO quotes (name, email, phone, address, service, details, attachments)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, phone, address, service, details, json.dumps(attachment_names)))
        quote_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
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
    """Handle newsletter subscription via AJAX"""
    try:
        email = request.form.get('email', '').strip()
        
        if not email:
            return jsonify({'success': False, 'message': 'Please provide a valid email address.'}), 400
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO newsletter_subscriptions (email) VALUES (?)', (email,))
            conn.commit()
            
            update_stat('newsletter_subscribers', 1)
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'message': 'This email is already subscribed to our newsletter.'}), 400
        
        conn.close()
        
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
    """Add a new comment/review"""
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '').strip()
        
        if not all([name, email, rating, comment]):
            return jsonify({'success': False, 'message': 'Please fill in all fields.'}), 400
        
        if rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5.'}), 400
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO comments (name, email, rating, comment)
            VALUES (?, ?, ?, ?)
        ''', (name, email, rating, comment))
        conn.commit()
        conn.close()
        
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
    """Get approved comments for display"""
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT name, rating, comment, created_at
        FROM comments
        WHERE approved = 1
        ORDER BY created_at DESC
        LIMIT 10
    ''').fetchall()
    conn.close()
    
    return jsonify([{
        'name': comment['name'],
        'rating': comment['rating'],
        'comment': comment['comment'],
        'date': comment['created_at']
    } for comment in comments])

@app.route('/api/stats')
def get_stats():
    """Get business statistics"""
    conn = get_db_connection()
    stats = conn.execute('SELECT stat_name, stat_value FROM business_stats').fetchall()
    conn.close()
    
    return jsonify({stat['stat_name']: stat['stat_value'] for stat in stats})

@app.route('/admin/login', methods=['GET', 'POST'])
@ip_whitelist_required
def admin_login():
    """Admin login page with rate limiting"""
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
            
            conn = get_db_connection()
            admin_2fa = conn.execute('SELECT * FROM admin_2fa WHERE id = 1').fetchone()
            conn.close()

            if admin_2fa and admin_2fa['is_enabled']:
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
@ip_whitelist_required
def verify_2fa():
    """Verify 2FA token"""
    if 'temp_admin_login' not in session:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        backup_code = request.form.get('backup_code')
        
        conn = get_db_connection()
        admin_2fa = conn.execute('SELECT * FROM admin_2fa WHERE id = 1').fetchone()
        
        if admin_2fa:
            verified = False
            
            if token:
                totp = pyotp.TOTP(admin_2fa['secret_key'])
                verified = totp.verify(token)
            
            elif backup_code:
                backup_codes = json.loads(admin_2fa['backup_codes'] or '[]')
                if backup_code.upper() in backup_codes:
                    backup_codes.remove(backup_code.upper())
                    conn.execute('UPDATE admin_2fa SET backup_codes = ? WHERE id = 1', 
                               (json.dumps(backup_codes),))
                    conn.commit()
                    verified = True
            
            if verified:
                session.pop('temp_admin_login', None)
                session['admin_logged_in'] = True
                session['last_activity'] = datetime.now().isoformat()
                conn.close()
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
        
        conn.close()
        flash('Invalid token or backup code.', 'danger')
    
    return render_template('admin_2fa_verify.html')

@app.route('/admin/setup-2fa')
@login_required
@ip_whitelist_required
def setup_2fa():
    """Setup 2FA for admin"""
    conn = get_db_connection()
    existing_2fa = conn.execute('SELECT * FROM admin_2fa WHERE id = 1').fetchone()
    
    if not existing_2fa:
        secret = pyotp.random_base32()
        conn.execute('INSERT INTO admin_2fa (id, secret_key) VALUES (1, ?)', (secret,))
        conn.commit()
    else:
        secret = existing_2fa['secret_key']
    
    conn.close()
    
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
@ip_whitelist_required
def enable_2fa():
    """Enable 2FA after verification"""
    token = request.form.get('token')
    
    conn = get_db_connection()
    admin_2fa = conn.execute('SELECT secret_key FROM admin_2fa WHERE id = 1').fetchone()
    
    if admin_2fa:
        totp = pyotp.TOTP(admin_2fa['secret_key'])
        if totp.verify(token):
            backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
            conn.execute('''
                UPDATE admin_2fa 
                SET is_enabled = 1, backup_codes = ?
                WHERE id = 1
            ''', (json.dumps(backup_codes),))
            conn.commit()
            conn.close()
            
            flash('2FA enabled successfully! Save your backup codes.', 'success')
            return render_template('admin_2fa_backup_codes.html', backup_codes=backup_codes)
        else:
            conn.close()
            flash('Invalid token. Please try again.', 'danger')
            return redirect(url_for('setup_2fa'))
    
    conn.close()
    flash('2FA setup error.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
@ip_whitelist_required
def admin_logout():
    """Admin logout"""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
@ip_whitelist_required
def admin_dashboard():
    """Admin dashboard"""
    conn = get_db_connection()
    
    stats = conn.execute('SELECT stat_name, stat_value FROM business_stats').fetchall()
    stats_dict = {stat['stat_name']: stat['stat_value'] for stat in stats}
    
    quotes = conn.execute('''
        SELECT * FROM quotes
        ORDER BY created_at DESC
        LIMIT 10
    ''').fetchall()
    
    pending_comments = conn.execute('''
        SELECT * FROM comments
        WHERE approved = 0
        ORDER BY created_at DESC
    ''').fetchall()
    
    newsletter_count = conn.execute('SELECT COUNT(*) as count FROM newsletter_subscriptions WHERE active = 1').fetchone()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         stats=stats_dict,
                         quotes=quotes,
                         pending_comments=pending_comments,
                         newsletter_count=newsletter_count['count'])

@app.route('/admin/quotes')
@login_required
@ip_whitelist_required
def admin_quotes():
    """View all quotes"""
    conn = get_db_connection()
    quotes = conn.execute('''
        SELECT * FROM quotes
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin_quotes.html', quotes=quotes)

@app.route('/admin/quotes/<int:quote_id>/status', methods=['POST'])
@login_required
@ip_whitelist_required
def update_quote_status(quote_id):
    """Update quote status"""
    new_status = request.form.get('status')
    
    conn = get_db_connection()
    conn.execute('''
        UPDATE quotes
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_status, quote_id))
    conn.commit()
    conn.close()
    
    if new_status == 'completed':
        update_stat('jobs_completed', 1)
    
    flash(f'Quote #{quote_id} status updated to {new_status}', 'success')
    return redirect(url_for('admin_quotes'))

@app.route('/admin/quotes/<int:quote_id>/details', methods=['GET'])
@login_required
@ip_whitelist_required
def get_quote_details(quote_id):
    """Fetch details for a specific quote"""
    conn = get_db_connection()
    quote = conn.execute('SELECT * FROM quotes WHERE id = ?', (quote_id,)).fetchone()
    conn.close()
    
    if not quote:
        return jsonify({'success': False, 'message': 'Quote not found'}), 404
    
    return jsonify({
        'success': True,
        'id': quote['id'],
        'name': quote['name'],
        'email': quote['email'],
        'phone': quote['phone'],
        'address': quote['address'],
        'service': quote['service'],
        'details': quote['details'],
        'status': quote['status'],
        'created_at': quote['created_at'],
        'attachments': quote['attachments']
    })

@app.route('/api/export/newsletter', methods=['GET'])
@login_required
@ip_whitelist_required
def export_newsletter():
    """Export newsletter subscribers as CSV"""
    try:
        conn = get_db_connection()
        subscribers = conn.execute('''
            SELECT email, subscribed_at, active
            FROM newsletter_subscriptions
            ORDER BY subscribed_at DESC
        ''').fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Email', 'Subscribed Date', 'Status'])
        
        for subscriber in subscribers:
            writer.writerow([
                subscriber['email'],
                subscriber['subscribed_at'],
                'Active' if subscriber['active'] else 'Inactive'
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
    """Check if required templates exist"""
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
@ip_whitelist_required
def admin_comments():
    """View all comments"""
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT * FROM comments
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin_comments.html', comments=comments)

@app.route('/admin/comments/<int:comment_id>/approve', methods=['POST'])
@login_required
@ip_whitelist_required
def approve_comment(comment_id):
    """Approve a comment"""
    conn = get_db_connection()
    conn.execute('UPDATE comments SET approved = 1 WHERE id = ?', (comment_id,))
    conn.commit()
    conn.close()
    
    flash('Comment approved successfully!', 'success')
    return redirect(url_for('admin_comments'))

@app.route('/admin/comments/<int:comment_id>/delete', methods=['POST'])
@login_required
@ip_whitelist_required
def delete_comment(comment_id):
    """Delete a comment"""
    conn = get_db_connection()
    conn.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    conn.commit()
    conn.close()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('admin_comments'))

@app.route('/admin/newsletter')
@login_required
@ip_whitelist_required
def admin_newsletter():
    """View newsletter subscribers"""
    conn = get_db_connection()
    subscribers = conn.execute('''
        SELECT * FROM newsletter_subscriptions
        WHERE active = 1
        ORDER BY subscribed_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin_newsletter.html', subscribers=subscribers)

@app.route('/admin/stats', methods=['GET', 'POST'])
@login_required
@ip_whitelist_required
def admin_stats():
    """Manage business statistics"""
    if request.method == 'POST':
        stat_name = request.form.get('stat_name')
        stat_value = request.form.get('stat_value', type=int)
        
        conn = get_db_connection()
        conn.execute('''
            UPDATE business_stats
            SET stat_value = ?, updated_at = CURRENT_TIMESTAMP
            WHERE stat_name = ?
        ''', (stat_value, stat_name))
        conn.commit()
        conn.close()
        
        flash('Statistics updated successfully!', 'success')
        return redirect(url_for('admin_stats'))
    
    conn = get_db_connection()
    stats = conn.execute('SELECT * FROM business_stats ORDER BY stat_name').fetchall()
    conn.close()
    
    return render_template('admin_stats.html', stats=stats)

@app.route('/api/performance_data')
@login_required
@ip_whitelist_required
def get_performance_data():
    """Fetch data for Business Performance chart based on period"""
    period = request.args.get('period', 'monthly')
    conn = get_db_connection()

    if period == 'daily':
        query = '''
            SELECT 
                date(created_at) as period,
                COUNT(*) as bookings,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as jobs_completed
            FROM quotes
            WHERE created_at >= date('now', '-30 days')
            GROUP BY date(created_at)
            ORDER BY period ASC
        '''
    elif period == 'weekly':
        query = '''
            SELECT 
                strftime('%Y-%W', created_at) as period,
                COUNT(*) as bookings,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as jobs_completed
            FROM quotes
            WHERE created_at >= date('now', '-12 weeks')
            GROUP BY strftime('%Y-%W', created_at)
            ORDER BY period ASC
        '''
    elif period == '90':
        query = '''
            SELECT 
                date(created_at) as period,
                COUNT(*) as bookings,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as jobs_completed
            FROM quotes
            WHERE created_at >= date('now', '-90 days')
            GROUP BY date(created_at)
            ORDER BY period ASC
        '''
    elif period == '365':
        query = '''
            SELECT 
                strftime('%Y-%m', created_at) as period,
                COUNT(*) as bookings,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as jobs_completed
            FROM quotes
            WHERE created_at >= date('now', '-1 year')
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY period ASC
        '''
    else:
        query = '''
            SELECT 
                strftime('%Y-%m', created_at) as period,
                COUNT(*) as bookings,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as jobs_completed
            FROM quotes
            WHERE created_at >= date('now', '-6 months')
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY period ASC
        '''

    performance_data = conn.execute(query).fetchall()
    conn.close()

    labels = [row['period'] for row in performance_data]
    bookings = [row['bookings'] for row in performance_data]
    jobs_completed = [row['jobs_completed'] for row in performance_data]

    return jsonify({
        'labels': labels,
        'bookings': bookings,
        'jobs_completed': jobs_completed
    })

@app.route('/api/service_distribution')
@login_required
@ip_whitelist_required
def get_service_distribution():
    """Fetch data for Service Distribution chart"""
    conn = get_db_connection()
    
    service_data = conn.execute('''
        SELECT 
            service,
            COUNT(*) as count
        FROM quotes
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        GROUP BY service
    ''').fetchall()
    
    conn.close()
    
    labels = [row['service'] for row in service_data]
    counts = [row['count'] for row in service_data]
    
    return jsonify({
        'labels': labels,
        'data': counts
    })

@app.route('/admin/quotes/<int:quote_id>/delete', methods=['POST'])
@login_required
@ip_whitelist_required
def admin_delete_quote(quote_id):
    """Delete a quote"""
    conn = get_db_connection()
    conn.execute('DELETE FROM quotes WHERE id = ?', (quote_id,))
    conn.commit()
    conn.close()
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
    init_db()
    app.run(debug=True)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

with app.app_context():
    db.create_all()
