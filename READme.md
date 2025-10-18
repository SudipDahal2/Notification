# Flask + PostgreSQL Authentication System Setup Guide

## Prerequisites
✅ PostgreSQL installed on Windows  
✅ Python installed (3.8 or higher)  
✅ Node.js installed (for React frontend - optional if using Claude artifact)

---

## Step 1: Set Up PostgreSQL Database

### 1.1 Open PostgreSQL Command Line (psql)
- Search for "SQL Shell (psql)" in Windows Start Menu
- Press Enter to accept defaults for Server, Database, Port, Username
- Enter your PostgreSQL password

### 1.2 Create Database and Table
```sql
-- Create the database
CREATE DATABASE auth_app;

-- Connect to the database
\c auth_app

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Verify table was created
\dt

-- Exit psql
\q
```

---

## Step 2: Set Up Flask Backend

### 2.1 Create Project Folder
```bash
mkdir auth-app
cd auth-app
```

### 2.2 Create Python Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
```

### 2.3 Install Required Packages
Create a file named `requirements.txt` with:
```
Flask==3.0.0
flask-cors==4.0.0
psycopg2==2.9.9
bcrypt==4.1.2
PyJWT==2.8.0
```

Install packages:
```bash
pip install -r requirements.txt
```

### 2.4 Create Flask Application
Create a file named `app.py` and copy the Flask backend code from the artifact above.

### 2.5 Configure Database Connection
Open `app.py` and update the database configuration:
```python
DB_CONFIG = {
    'host': 'localhost',
    'database': 'auth_app',
    'user': 'postgres',
    'password': 'YOUR_POSTGRESQL_PASSWORD'  # Change this!
}
```

Also change the secret key:
```python
app.config['SECRET_KEY'] = 'your-random-secret-key-here'  # Change this!
```

---

## Step 3: Run the Backend

```bash
python app.py
```

You should see:
```
Database initialized successfully!
Flask server starting on http://localhost:5000
```

---

## Step 4: Test the Backend

### Using Browser or Postman

**Health Check:**
```
GET http://localhost:5000/api/health
```

**Sign Up:**
```
POST http://localhost:5000/api/signup
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
}
```

**Login:**
```
POST http://localhost:5000/api/login
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "password123"
}
```

---

## Step 5: Use the React Frontend

The React frontend is already created in the Claude artifact above. It will:
- Automatically detect if Flask is running
- Show connection status
- Handle signup and login
- Store session in memory

Just make sure Flask is running on `http://localhost:5000`

---

## Troubleshooting

### Error: "psycopg2 not found"
```bash
pip install psycopg2-binary
```

### Error: "Connection refused"
- Make sure PostgreSQL is running
- Check if Flask server is running on port 5000
- Verify database credentials in `app.py`

### Error: "CORS error in browser"
- Make sure `flask-cors` is installed
- Restart Flask server

### Port 5000 already in use:
```python
# In app.py, change the port:
app.run(debug=True, port=5001)

# Also update API_URL in React frontend:
const API_URL = 'http://localhost:5001/api';
```

---

## Project Structure

```
auth-app/
├── venv/                  # Virtual environment
├── app.py                 # Flask backend
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

---

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | /api/health | Check API status | No |
| POST | /api/signup | Create new user | No |
| POST | /api/login | Login user | No |
| GET | /api/user | Get current user | Yes |
| GET | /api/users | Get all users | No |

---

## Security Notes

1. **Change the SECRET_KEY** in production
2. **Use environment variables** for sensitive data
3. **Enable HTTPS** in production
4. **Add rate limiting** for login attempts
5. **Implement email verification** for signups
6. **Add password reset functionality**

---

## Next Steps

- [ ] Add password reset functionality
- [ ] Implement email verification
- [ ] Add user profile update
- [ ] Add role-based access control
- [ ] Deploy to production server

---

## Need Help?

- PostgreSQL Docs: https://www.postgresql.org/docs/
- Flask Docs: https://flask.palletsprojects.com/
- psycopg2 Docs: https://www.psycopg.org/docs/