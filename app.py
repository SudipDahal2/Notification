from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import jwt
import datetime
from functools import wraps
from dotenv import load_dotenv
import os
import urllib.parse

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'my-super-secret-key-12345')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['DEBUG'] = False
app.config['ENV'] = 'production'

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://notification-y02u.onrender.com",
            "https://sudipdahal.me"
        ],
        "methods": ["GET", "POST", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

if os.getenv('DATABASE_URL'):
    parsed_url = urllib.parse.urlparse(os.getenv('DATABASE_URL'))
    DB_CONFIG = {
        'host': parsed_url.hostname,
        'database': parsed_url.path.lstrip('/'),
        'user': parsed_url.username,
        'password': parsed_url.password,
        'port': parsed_url.port or 5432,
        'sslmode': 'require'
    }
else:
    DB_CONFIG = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'database': os.getenv('DB_DATABASE', 'auth_app'),
        'user': os.getenv('DB_USER', 'postgres'),
        'password': os.getenv('DB_PASSWORD', 'SORA300'),
        'sslmode': 'require' if os.getenv('FLASK_ENV') == 'production' else 'disable'
    }

ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'yourname@gmail.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'MyStrongPass123')

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

def init_db():
    max_retries = 5
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            print("Creating users table...")
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            print("✅ Users table created/verified")
            
            print(f"Checking for admin user: {ADMIN_EMAIL}")
            cur.execute('SELECT * FROM users WHERE email = %s', (ADMIN_EMAIL,))
            admin = cur.fetchone()
            
            if not admin:
                print("Creating admin account...")
                hashed_password = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
                cur.execute(
                    'INSERT INTO users (name, email, password, is_admin) VALUES (%s, %s, %s, %s)',
                    ('Admin', ADMIN_EMAIL, hashed_password.decode('utf-8'), True)
                )
                conn.commit()
                print(f"✅ Admin account created: {ADMIN_EMAIL}")
            else:
                print(f"✅ Admin account already exists: {ADMIN_EMAIL}")
            
            cur.close()
            conn.close()
            print("✅ Database initialization successful!")
            return True
            
        except Exception as e:
            retry_count += 1
            print(f"⚠️ Database init attempt {retry_count}/{max_retries} failed: {e}")
            if retry_count < max_retries:
                import time
                time.sleep(2)
            else:
                print(f"❌ Database initialization failed after {max_retries} attempts: {e}")
                return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth_page'))
        if not session.get('is_admin', False):
            return render_template('403.html'), 403
        return f(*args, **kwargs)
    return decorated_function

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not name or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(name) < 2:
            return jsonify({'error': 'Name must be at least 2 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                'INSERT INTO users (name, email, password, is_admin) VALUES (%s, %s, %s, %s) RETURNING id, name, email, is_admin',
                (name, email, hashed_password.decode('utf-8'), False)
            )
            user = cur.fetchone()
            conn.commit()
            
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['is_admin'] = user['is_admin']
            session.permanent = True
            
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'message': 'User created successfully',
                'token': token,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'is_admin': user['is_admin']
                },
                'redirect': '/'
            }), 201
            
        except psycopg2.IntegrityError:
            conn.rollback()
            return jsonify({'error': 'Email already exists'}), 400
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({'error': 'An error occurred during signup'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['user_email'] = user['email']
        session['is_admin'] = user.get('is_admin', False)
        session.permanent = True
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        redirect_url = '/admin' if user.get('is_admin', False) else '/'
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'is_admin': user.get('is_admin', False)
            },
            'redirect': redirect_url
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/api/user', methods=['GET'])
@token_required
def get_user(current_user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('SELECT id, name, email, is_admin, created_at FROM users WHERE id = %s', (current_user_id,))
        user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user}), 200
        
    except Exception as e:
        print(f"Get user error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/current-user', methods=['GET'])
def get_current_user():
    if 'user_id' in session:
        return jsonify({
            'user': {
                'id': session['user_id'],
                'name': session['user_name'],
                'email': session['user_email'],
                'is_admin': session.get('is_admin', False)
            }
        }), 200
    return jsonify({'error': 'Not logged in'}), 401

@app.route('/api/users', methods=['GET'])
def get_all_users():
    if 'user_id' not in session or not session.get('is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('SELECT id, name, email, is_admin, created_at FROM users ORDER BY created_at DESC')
        users = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({'users': users}), 200
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('DELETE FROM users WHERE id = %s AND is_admin = FALSE', (user_id,))
        conn.commit()
        
        cur.close()
        conn.close()
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        print(f"Delete user error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
        conn.close()
        return jsonify({'status': 'API is running', 'database': 'connected'}), 200
    except:
        return jsonify({'status': 'API is running', 'database': 'disconnected'}), 500

try:
    print("Attempting database initialization...")
    init_db()
except Exception as e:
    print(f"Warning: Could not initialize database on startup: {e}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)