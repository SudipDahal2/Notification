import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'database': 'auth_app',
    'user': 'postgres',
    'password': 'SORA300'  # Your PostgreSQL password
}

try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Add is_admin column
    cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE')
    conn.commit()
    
    print("✅ Database updated successfully!")
    print("You can now run: python app.py")
    
    cur.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")