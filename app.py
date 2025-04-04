from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database setup
def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Register User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return "User already exists!"
    return render_template('register.html')

# Login User
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password, user[0]):
                session['username'] = username
                session['original_password'] = request.form['password']
                session['hashed_password'] = user[0]
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="Invalid credentials! Please try again.")
    return render_template('login.html')

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html', 
                           username=session['username'], 
                           original_password=session.get('original_password', ''),
                           hashed_password=session.get('hashed_password', ''))

# Hash Converter
@app.route('/hash_converter', methods=['POST'])
def hash_converter():
    if 'username' not in session:
        return redirect(url_for('login'))

    text_to_hash = request.form.get('text_to_hash')

    if text_to_hash:
        hashed_version = bcrypt.hashpw(text_to_hash.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        return render_template('dashboard.html', 
                               username=session['username'],
                               original_password=session.get('original_password', ''),
                               hashed_password=session.get('hashed_password', ''),
                               converted_text=text_to_hash, 
                               converted_hash=hashed_version)

    return redirect(url_for('dashboard'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

