from flask import Flask, render_template, request, jsonify, redirect, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import re
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'digital-safety-secret-key-2024'
DATABASE = os.path.join(os.path.dirname(__file__), 'instance', 'digital_safety.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    with sqlite3.connect(DATABASE) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS scam_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                report_type TEXT NOT NULL,
                content TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'suspicious',
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS url_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT,
                risk_score INTEGER,
                flags TEXT,
                checked_at TEXT DEFAULT (datetime('now'))
            );
        ''')
        existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?,?,?,?)",
                ('admin', 'admin@digitalsafety.com', generate_password_hash('admin123'), 1)
            )
            conn.commit()

SCAM_KEYWORDS = [
    'urgent','verify your account','click here immediately','limited time offer',
    'you have won','congratulations you','free gift','act now','risk free',
    'guaranteed','no risk','this is not spam','dear friend','dear valued customer',
    'bank account','social security','credit card number','your password',
    'suspended','unauthorized access','confirm your identity','security alert',
    'unusual activity','your account will be','login attempt','verify immediately',
    'claim your prize','wire transfer','western union','money gram',
    'nigerian prince','inheritance','million dollars','lottery winner',
    'irs notice','tax refund','government grant','bitcoin','cryptocurrency investment',
    'double your money','make money fast','work from home earn','get rich quick'
]

SAFE_DOMAINS = [
    'google.com','microsoft.com','apple.com','amazon.com','facebook.com',
    'twitter.com','linkedin.com','github.com','stackoverflow.com','youtube.com',
    'wikipedia.org','reddit.com','netflix.com','instagram.com','whatsapp.com'
]

PHISHING_PATTERNS = [
    r'paypa1\.', r'arnazon\.', r'g00gle\.', r'micros0ft\.', r'app1e\.com',
    r'secure-.*\.tk', r'login-.*\.ml', r'verify-.*\.ga', r'account-.*\.cf',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$',
]

def analyze_url(url):
    flags = []; risk_score = 0
    for domain in SAFE_DOMAINS:
        if domain in url.lower():
            return {'result': 'safe', 'risk_score': 5, 'flags': ['Known trusted domain']}
    if not url.startswith('https://'):
        flags.append('No HTTPS encryption'); risk_score += 20
    for p in PHISHING_PATTERNS:
        if re.search(p, url, re.IGNORECASE):
            flags.append(f'Suspicious pattern detected'); risk_score += 30
    if len(url) > 100:
        flags.append('Unusually long URL'); risk_score += 10
    try:
        dp = url.split('/')[2]
        if dp.count('.') > 3:
            flags.append('Excessive subdomains'); risk_score += 15
    except: pass
    if re.search(r'[@%]', url):
        flags.append('Special characters in URL'); risk_score += 25
    if re.search(r'bit\.ly|tinyurl\.com', url):
        flags.append('URL shortener detected'); risk_score += 15
    if risk_score >= 60: result = 'dangerous'
    elif risk_score >= 25: result = 'suspicious'
    else: result = 'safe'
    return {'result': result, 'risk_score': min(risk_score, 100), 'flags': flags or ['No threats detected']}

def analyze_message(text):
    tl = text.lower(); found = []; risk_score = 0
    for kw in SCAM_KEYWORDS:
        if kw in tl:
            found.append(kw); risk_score += 12
    for p in [r'within \d+ hours?', r'expires? today', r'last chance', r'final notice']:
        if re.search(p, tl):
            found.append('Urgency language'); risk_score += 15
    urls = re.findall(r'http[s]?://\S+', text)
    if urls:
        found.append(f'{len(urls)} URL(s) found'); risk_score += 10
    for info in ['ssn','social security','credit card','cvv','pin number']:
        if info in tl:
            found.append(f'Requests sensitive info: {info}'); risk_score += 20
    if risk_score >= 60: result, verdict = 'dangerous', 'HIGH RISK — Strong scam indicators detected.'
    elif risk_score >= 25: result, verdict = 'suspicious', 'CAUTION — Suspicious characteristics found.'
    else: result, verdict = 'safe', 'LIKELY SAFE — No major scam indicators detected.'
    return {'result': result, 'risk_score': min(risk_score, 100), 'keywords_found': found, 'verdict': verdict}

def get_current_user():
    uid = session.get('user_id')
    if uid:
        return query_db('SELECT * FROM users WHERE id=?', [uid], one=True)
    return None

@app.route('/')
def home():
    return render_template('home.html', user=get_current_user())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        d = request.get_json()
        username, email, password = d.get('username','').strip(), d.get('email','').strip(), d.get('password','')
        if query_db('SELECT id FROM users WHERE username=?', [username], one=True):
            return jsonify({'success': False, 'message': 'Username already exists'})
        if query_db('SELECT id FROM users WHERE email=?', [email], one=True):
            return jsonify({'success': False, 'message': 'Email already registered'})
        uid = execute_db('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)',
                         [username, email, generate_password_hash(password)])
        session['user_id'] = uid
        return jsonify({'success': True})
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        d = request.get_json()
        user = query_db('SELECT * FROM users WHERE username=?', [d.get('username','')], one=True)
        if user and check_password_hash(user['password_hash'], d.get('password','')):
            session['user_id'] = user['id']
            return jsonify({'success': True, 'redirect': '/admin' if user['is_admin'] else '/'})
        return jsonify({'success': False, 'message': 'Invalid username or password'})
    return render_template('auth.html', mode='login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

@app.route('/url-checker')
def url_checker():
    return render_template('url_checker.html', user=get_current_user())

@app.route('/scam-detector')
def scam_detector():
    return render_template('scam_detector.html', user=get_current_user())

@app.route('/report')
def report_page():
    return render_template('report.html', user=get_current_user())

@app.route('/learn')
def learn():
    return render_template('learn.html', user=get_current_user())

@app.route('/admin')
def admin():
    user = get_current_user()
    if not user or not user['is_admin']:
        return redirect('/login')
    users = query_db('SELECT * FROM users ORDER BY created_at DESC')
    reports = query_db('SELECT r.*, u.username as reporter_name FROM scam_reports r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC')
    url_checks = query_db('SELECT * FROM url_checks ORDER BY checked_at DESC LIMIT 50')
    stats = {
        'total_users': query_db('SELECT COUNT(*) as c FROM users', one=True)['c'],
        'total_reports': query_db('SELECT COUNT(*) as c FROM scam_reports', one=True)['c'],
        'total_checks': query_db('SELECT COUNT(*) as c FROM url_checks', one=True)['c'],
        'dangerous_reports': query_db("SELECT COUNT(*) as c FROM scam_reports WHERE severity='dangerous'", one=True)['c'],
    }
    return render_template('admin.html', user=user, users=users, reports=reports, url_checks=url_checks, stats=stats)

@app.route('/api/check-url', methods=['POST'])
def api_check_url():
    url = request.get_json().get('url', '').strip()
    if not url: return jsonify({'error': 'No URL'}), 400
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    analysis = analyze_url(url)
    execute_db('INSERT INTO url_checks (url, result, risk_score, flags) VALUES (?,?,?,?)',
               [url, analysis['result'], analysis['risk_score'], json.dumps(analysis['flags'])])
    return jsonify(analysis)

@app.route('/api/check-message', methods=['POST'])
def api_check_message():
    text = request.get_json().get('text', '').strip()
    if not text: return jsonify({'error': 'No text'}), 400
    return jsonify(analyze_message(text))

@app.route('/api/submit-report', methods=['POST'])
def api_submit_report():
    d = request.get_json()
    user = get_current_user()
    rid = execute_db(
        'INSERT INTO scam_reports (user_id, report_type, content, description, severity) VALUES (?,?,?,?,?)',
        [user['id'] if user else None, d.get('type','url'), d.get('content',''), d.get('description',''), d.get('severity','suspicious')]
    )
    return jsonify({'success': True, 'id': rid})

@app.route('/api/admin/update-report', methods=['POST'])
def api_update_report():
    user = get_current_user()
    if not user or not user['is_admin']: return jsonify({'error': 'Unauthorized'}), 403
    d = request.get_json()
    execute_db('UPDATE scam_reports SET status=? WHERE id=?', [d.get('status'), d.get('id')])
    return jsonify({'success': True})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
