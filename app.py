from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import cv2
import numpy as np
from deepface import DeepFace
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SALT'] = b'PranavTyagi123'
app.config['UPLOAD_FOLDER'] = 'faces'

db_faces = [
    {"name": "Person1", "img_path": "pranav.png"}
]

# Create a database connection
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, secret TEXT)')
cur.execute('CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, username TEXT, password TEXT)')
conn.commit()


def hash_master_password(master_password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(master_password.encode())
    return digest.finalize()

def derive_key_from_hash(hashed_master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=app.config['SALT'],
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(hashed_master_password)

def encrypt_password(password, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_password).decode('utf-8')

def decrypt_password(encrypted_password, key):
    encrypted_password = base64.b64decode(encrypted_password.encode('utf-8'))
    iv = encrypted_password[:16]
    encrypted_password = encrypted_password[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_password) + decryptor.finalize()).decode('utf-8')

def preprocess_db_faces(db_faces):
    preprocessed_faces = []
    for face in db_faces:
        img = cv2.imread(face["img_path"])
        if img is not None:
            face["image"] = img
            preprocessed_faces.append(face)
    return preprocessed_faces

preprocessed_faces = preprocess_db_faces(db_faces)

def recognize_face(frame, preprocessed_faces):
    for face in preprocessed_faces:
        try:
            result = DeepFace.verify(frame, face["image"], model_name='VGG-Face', enforce_detection=False)
            if result["verified"]:
                return True
        except Exception as e:
            print(f"Recognition Error: {e}")
    return False



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
    file = request.files['image']
    signup_conn = sqlite3.connect('database.db')
    cur = signup_conn.cursor()
    cur.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cur.fetchone()
    if user:
        totp = pyotp.TOTP(user[4])
        if totp.verify(otp):
            session['password'] = user[3]
            filename = email+secure_filename(file.filename).split['.'][-1]
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
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

        hashed_master_password = session['password']
        key = derive_key_from_hash(hashed_master_password)
        encrypted_password = encrypt_password(password, key)

        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute('INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)', (session['id'], website, username, encrypted_password))
        conn.commit()
        cur.execute('SELECT * FROM passwords WHERE user_id = ?', (session['id'],))
        passwords = cur.fetchall()
        return redirect(url_for('dashboard'))
    else:
        if 'id' in session and 'password' in session:
            #Verify if id is valid by password check
            conn = sqlite3.connect('database.db')
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = ? AND password = ?', (session['id'], session['password']))
            user = cur.fetchone()
            if user:
                cur.execute('SELECT * FROM passwords WHERE user_id = ?', (session['id'],))
                passwords = cur.fetchall()

                hashed_master_password = session['password']
                key = derive_key_from_hash(hashed_master_password)

                passwords = [(password[2], password[3], decrypt_password(password[4], key)) for password in passwords]

                return render_template('dashboard.html', passwords=passwords)
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))

@app.route('/process_frame', methods=['POST'])
def process_frame():
    if 'frame' not in request.files:
        return jsonify({'recognized': False})

    frame = request.files['frame'].read()
    np_frame = np.frombuffer(frame, np.uint8)
    img = cv2.imdecode(np_frame, cv2.IMREAD_COLOR)

    recognized = recognize_face(img, db_faces)
    return jsonify({'recognized': recognized})

if __name__ == '__main__':
    app.run(debug=True)