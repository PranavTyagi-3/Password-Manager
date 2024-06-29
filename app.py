from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import bcrypt

app = Flask(__name__)
app.secret_key = 'secret'

# Create a database connection
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, secret TEXT)')
cur.execute('CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, username TEXT, password TEXT)')
conn.commit()

@app.route('/', methods=['GET'])
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get the data from the POST request
        user = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the user with current email and username exists in the database otherwise insert the record
        signup_conn = sqlite3.connect('database.db')
        cur = signup_conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ? OR email = ?', (user, email))
        usercheck = cur.fetchone()
        if usercheck:
            return redirect(url_for('signup', message='User already exists!'))
        
        else:
            # Save the password in hashed format
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (user, email, password_hash))
            signup_conn.commit()
            cur.execute('SELECT * FROM users WHERE email = ?', (email,))
            userFetch = cur.fetchone()
            session['id'] = userFetch[0]

            # Generate a secret key for the user
            secret = pyotp.random_base32()
            cur.execute('UPDATE users SET secret = ? WHERE id = ?', (secret, session['id']))
            signup_conn.commit()
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(email, issuer_name="Secure Password Manager")
            qr = qrcode.make(uri)
            qr.save(f'static/qr/{user}.png')
            return render_template('otpVerification.html', qr=f'static/qr/{user}.png', email = email)
        
    return render_template('signup.html')

@app.route('/otpVerification', methods=['POST'])
def verify():
    # Get the data from the POST request
    otp = request.form['otp']
    email = request.form['email']
    signup_conn = sqlite3.connect('database.db')
    cur = signup_conn.cursor()
    cur.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cur.fetchone()
    if user:
        totp = pyotp.TOTP(user[4])
        if totp.verify(otp):
            session['password'] = user[3]
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('signup', message='Invalid OTP!'))
    else:
        return redirect(url_for('signup', message='Invalid credentials!'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the data from the POST request
        email = request.form['email']
        password = request.form['password']
        otp = request.form['otp']
        print(email, password)
        login_conn = sqlite3.connect('database.db')
        cur = login_conn.cursor()
        cur.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cur.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3]):
            # Check if the OTP entered by the user is valid
            totp = pyotp.TOTP(user[4])
            if totp.verify(otp):
                session['id'] = user[0]
                session['password'] = user[3]
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('login', message='Invalid OTP!'))
        else:
            return redirect(url_for('login', message='Invalid credentials!'))
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        # Get the data from the POST request
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']

        # Save the password in hashed format
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute('INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)', (session['id'], website, username, password_hash))
        conn.commit()
        cur.execute('SELECT * FROM passwords WHERE user_id = ?', (session['id'],))
        passwords = cur.fetchall()
        return render_template('dashboard.html', passwords=passwords)
    
    if 'id' in session and 'password' in session:
        #Verify if id is valid by password check
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = ? AND password = ?', (session['id'], session['password']))
        user = cur.fetchone()
        if user:
            cur.execute('SELECT * FROM passwords WHERE user_id = ?', (session['id'],))
            passwords = cur.fetchall()
            return render_template('dashboard.html', passwords=passwords)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True)