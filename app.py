from flask import Flask, render_template, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'divyanshi_secret_key_2024')

# SQLite Database Setup
def init_db():
    conn = sqlite3.connect('career_guidance.db')
    cur = conn.cursor()
    
    # Create students table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)
    
    conn.commit()
    conn.close()

# Initialize database when app starts
init_db()

def get_db():
    conn = sqlite3.connect('career_guidance.db')
    conn.row_factory = sqlite3.Row
    return conn


# ========== ROUTE 1: HOME PAGE ==========
@app.route('/')
def home():
    return render_template('index.html')


# ========== ROUTE 2: LOGIN/SIGNUP PAGE ==========
@app.route('/loginpage')
def loginpage():
    return render_template('loginpage.html')


# ========== ROUTE 3: SIGNUP ==========
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not email or not password:
        return "❌ All fields are required!"
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO students (username, email, password) VALUES (?, ?, ?)", 
                   (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        # Show success page
        return render_template('success_signup.html', username=username)
    
    except sqlite3.IntegrityError:
        conn.close()
        return "❌ Email already registered! Please login instead."
    
    except Exception as e:
        conn.close()
        return f"❌ Error: {str(e)}"


# ========== ROUTE 4: LOGIN ==========
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM students WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        # Store user info in session
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['email'] = user['email']
        
        # Show success page
        return render_template('success_login.html', email=email, username=user['username'])
    else:
        return render_template('loginpage.html', error="❌ Invalid email or password.")


# ========== ROUTE 5: LOGOUT ==========
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ========== ROUTE 6: FORGOT PASSWORD (Step 1 - Enter Email) ==========
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM students WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()
        
        if not user:
            return "❌ Email not found. Please try again or sign up."
        else:
            # Generate 6-digit OTP
            otp = random.randint(100000, 999999)
            print(f"\n🔑 Generated OTP for {email}: {otp}\n")
            
            # Store OTP and email in session
            session['otp'] = otp
            session['reset_email'] = email
            
            # Show OTP entry page
            return render_template('enterotp.html', email=email)
    
    # GET request - show forgot password page
    return render_template('forgetpasss.html')


# ========== ROUTE 7: VERIFY OTP (Step 2) ==========
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered_otp = request.form.get('otp', '').strip()
    email = session.get('reset_email')
    original_otp = session.get('otp')
    
    if not email or not original_otp:
        return "❌ Session expired. Please start again."
    
    # Check if OTP matches
    if entered_otp == str(original_otp):
        # OTP correct - show reset password page
        return render_template('reset_password.html', email=email)
    else:
        # Wrong OTP - show error on same page
        return render_template('enterotp.html', email=email, error="❌ Invalid OTP. Please try again.")


# ========== ROUTE 8: RESET PASSWORD (Step 3) ==========
@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email', '').strip()
    new_password = request.form.get('new_password', '').strip()
    
    # SECURITY: Verify OTP session exists and email matches
    session_email = session.get('reset_email')
    session_otp = session.get('otp')
    
    if not session_email or not session_otp:
        return "❌ Session expired. Please start the password reset process again."
    
    if email != session_email:
        return "❌ Invalid request. Email does not match the verified session."
    
    if not new_password:
        return render_template('reset_password.html', email=email, error="Password cannot be empty!")
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Hash and update password
        hashed_password = generate_password_hash(new_password)
        cur.execute("UPDATE students SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()
        
        # Clear session
        session.pop('otp', None)
        session.pop('reset_email', None)
        
        # Show success page
        return render_template('success_password.html', email=email)
    
    except Exception as e:
        conn.close()
        return render_template('reset_password.html', email=email, error=f"Error: {str(e)}")


# ========== ROUTE 9: EXPLORE CAREERS ==========
@app.route('/explore')
def explore():
    return render_template('explore.html')


# ========== ROUTE 10: COURSE LIST ==========
@app.route('/courselist')
def courselist():
    return render_template('courselist.html')


# ========== ROUTE 11: BUILD PROFILE ==========
@app.route('/buildprofile')
def buildprofile():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('loginpage'))
    return render_template('buildprofile.html')


# ========== ROUTE 12: REGISTER FORM ==========
@app.route('/register_form', methods=['GET', 'POST'])
def register_form():
    if request.method == 'POST':
        # Handle career assessment form submission
        return render_template('successform.html')
    return render_template('register_form.html')


# ========== CAREER DETAIL PAGES ==========
@app.route('/btech')
def btech():
    return render_template('B.Tech.html')

@app.route('/bca')
def bca():
    return render_template('BCA.html')

@app.route('/bcom')
def bcom():
    return render_template('B.COM.html')

@app.route('/bsc')
def bsc():
    return render_template('B.sc.html')

@app.route('/bba')
def bba():
    return render_template('Bba.html')

@app.route('/ca')
def ca():
    return render_template('CA.html')

@app.route('/mbbs')
def mbbs():
    return render_template('MBBS.html')

@app.route('/nursing')
def nursing():
    return render_template('nursing.html')

@app.route('/pharmacy')
def pharmacy():
    return render_template('pharmacy.html')

@app.route('/about')
def about():
    return render_template('about.html')


# ========== RUN THE APP ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
