# challenges/web_challenge_3.py
import sqlite3
from flask import Flask, request, render_template, render_template_string, redirect, url_for

app = Flask(__name__, template_folder='../templates')

# --- Database for this specific challenge ---
def setup_challenge_database():
    conn = sqlite3.connect('challenge3.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )''')
    # Add a dummy user
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecretpassword123')")
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # This is the vulnerable part of the code
        conn = sqlite3.connect('challenge3.db')
        cursor = conn.cursor()
        
        # The query is built by concatenating strings, which is insecure
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except sqlite3.Error as e:
            user = None
            print(f"SQL Error: {e}") # For debugging on the server side
            
        conn.close()
        
        if user:
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
            
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', flag="flag{w3lc0m3_adm1n_y0u_h4v3_b33n_pwn3d}")

if __name__ == '__main__':
    setup_challenge_database()
    app.run(host='0.0.0.0', port=5003, debug=True)
