"""
ShieldAI — AI-Driven Scam & Fraud Protection System
Backend: Python Flask + MySQL
File: app.py
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import mysql.connector
import re
import json
import hashlib
import datetime
import random
import string
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ═══════════════════════════════════════════════════════
# DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',    # <-- Change this
    'database': 'shieldai_db',
    'charset': 'utf8mb4',
    'autocommit': True
}

def get_db():
    """Get a database connection."""
    return mysql.connector.connect(**DB_CONFIG)


# ═══════════════════════════════════════════════════════
# CLASS: DatabaseManager
# Handles all DB CRUD operations
# ═══════════════════════════════════════════════════════

class DatabaseManager:
    """Manages all database interactions for ShieldAI."""

    def __init__(self, config: dict):
        self.config = config

    def connect(self):
        return mysql.connector.connect(**self.config)

    def execute_query(self, query: str, params: tuple = (), fetchone: bool = False):
        """Execute a query and return results."""
        conn = self.connect()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        result = cursor.fetchone() if fetchone else cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        return result

    def execute_insert(self, query: str, params: tuple) -> int:
        """Execute an INSERT and return the last inserted ID."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        last_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return last_id

db = DatabaseManager(DB_CONFIG)


# ═══════════════════════════════════════════════════════
# CLASS: ThreatAnalyzer
# Core AI logic for detecting scams and phishing
# ═══════════════════════════════════════════════════════

class ThreatAnalyzer:
    """
    Analyzes text/URLs for scam indicators using
    keyword matching, pattern recognition, and heuristics.
    """

    # Scam keyword dictionary with weights
    SCAM_KEYWORDS = {
        # Phishing indicators
        'otp': 25, 'verify account': 30, 'suspended': 20, 'confirm your details': 25,
        'login immediately': 30, 'update payment': 25, 'click here': 15,
        'your account will be': 20, 'security alert': 15,

        # Financial fraud
        'you have won': 35, 'lottery': 30, 'prize money': 30, 'free money': 35,
        'guaranteed returns': 35, '100% profit': 40, 'double your money': 40,
        'advance fee': 35, 'pay small amount': 30, 'claim your reward': 30,
        'bitcoin investment': 35, 'crypto profit': 30,

        # Urgency / social engineering
        'urgent': 15, 'act now': 20, 'limited time': 20, 'expires today': 25,
        'last chance': 20, 'immediately': 15, 'final warning': 25,

        # Personal info harvesting
        'send your bank': 40, 'share your card': 40, 'cvv': 40,
        'bank account number': 40, 'password': 20, 'pin number': 35,

        # Misinformation
        'cure for cancer': 30, 'doctors hate': 25, 'government hiding': 20,
        'miracle cure': 25, 'scientists confirmed': 10,
    }

    SAFE_DOMAINS = [
        'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
        'axisbank.com', 'amazon.in', 'amazon.com', 'flipkart.com',
        'google.com', 'irctc.co.in', 'incometax.gov.in', 'uidai.gov.in',
        'npci.org.in', 'rbi.org.in', 'paytm.com', 'phonepe.com',
    ]

    SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click']

    PHISHING_PATTERNS = [
        r'(?:sbi|hdfc|icici|axis|paytm)[\-\_]?(?:secure|login|verify|update)',
        r'bank[\-\_]?(?:account|login|verify|secure)',
        r'(?:click|tap|visit)[\s]+(?:here|now|this)',
        r'(?:free|win|won|prize|reward)[\s\!\!]+',
        r'\b(?:otp|pin|cvv|password)\b.*(?:share|send|enter|provide)',
        r'₹\d+[\s]*(?:lakh|crore|k)\s*(?:won|prize|reward|guaranteed)',
    ]

    def analyze_text(self, text: str) -> dict:
        """Main analysis method — returns threat assessment dict."""
        text_lower = text.lower()
        score = 0
        triggers = []
        threat_types = []

        # Keyword scoring
        for keyword, weight in self.SCAM_KEYWORDS.items():
            if keyword in text_lower:
                score += weight
                triggers.append(keyword)

        # Regex pattern matching
        for pattern in self.PHISHING_PATTERNS:
            if re.search(pattern, text_lower):
                score += 20
                if 'otp' in pattern or 'bank' in pattern:
                    threat_types.append('phishing')
                elif 'free' in pattern or 'won' in pattern:
                    threat_types.append('lottery_fraud')

        # Classify threat types
        if any(k in text_lower for k in ['otp', 'verify account', 'login', 'password', 'cvv']):
            if 'phishing' not in threat_types:
                threat_types.append('phishing')

        if any(k in text_lower for k in ['won', 'lottery', 'prize', 'reward']):
            if 'lottery_fraud' not in threat_types:
                threat_types.append('lottery_fraud')

        if any(k in text_lower for k in ['investment', 'bitcoin', 'crypto', 'guaranteed', '100%']):
            threat_types.append('investment_scam')

        if any(k in text_lower for k in ['cure', 'miracle', 'government hiding', 'scientists']):
            threat_types.append('misinformation')

        # Clamp score
        score = min(100, score)

        # Risk level
        if score >= 70:
            risk = 'HIGH'
        elif score >= 40:
            risk = 'MEDIUM'
        elif score >= 15:
            risk = 'LOW'
        else:
            risk = 'SAFE'

        return {
            'score': score,
            'risk_level': risk,
            'threat_types': list(set(threat_types)),
            'triggers': list(set(triggers)),
            'is_threat': score >= 40,
            'recommendation': self._get_recommendation(risk, threat_types)
        }

    def analyze_url(self, url: str) -> dict:
        """Analyze a URL for phishing/fraud indicators."""
        score = 0
        flags = []

        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            domain = parsed.netloc.lower()
        except Exception:
            return {'score': 50, 'risk_level': 'MEDIUM', 'flags': ['Invalid URL format'], 'is_threat': True}

        # Check against safe domains
        for safe in self.SAFE_DOMAINS:
            if domain == safe or domain.endswith('.' + safe):
                return {
                    'score': 2, 'risk_level': 'SAFE',
                    'flags': ['Verified official domain'],
                    'is_threat': False,
                    'ssl': True,
                    'recommendation': 'This is a verified legitimate website.'
                }

        # Suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 30
                flags.append(f'Suspicious TLD: {tld}')

        # Brand impersonation
        brands = ['sbi', 'hdfc', 'icici', 'paytm', 'amazon', 'google', 'irctc', 'uidai']
        for brand in brands:
            if brand in domain and not any(domain == s or domain.endswith('.' + s) for s in self.SAFE_DOMAINS):
                score += 35
                flags.append(f'Brand impersonation: {brand}')

        # Hyphen abuse (common in phishing)
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            score += 15 * hyphen_count
            flags.append(f'Suspicious hyphen usage ({hyphen_count} hyphens)')

        # Check for scam words in URL
        scam_url_words = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'prize', 'free', 'win']
        for word in scam_url_words:
            if word in url.lower():
                score += 10
                flags.append(f'Scam keyword in URL: {word}')

        # Very new domain heuristic (can't check in demo but flagged)
        if len(domain) > 25:
            score += 10
            flags.append('Unusually long domain name')

        score = min(100, score)
        ssl = parsed.scheme == 'https'
        if not ssl:
            score += 15
            flags.append('No HTTPS encryption')

        return {
            'score': score,
            'risk_level': 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW' if score >= 15 else 'SAFE',
            'flags': flags,
            'is_threat': score >= 40,
            'ssl': ssl,
            'domain': domain,
            'recommendation': self._get_url_recommendation(score)
        }

    def _get_recommendation(self, risk: str, threat_types: list) -> str:
        recs = {
            'HIGH': "🚨 DO NOT engage with this content. Block the sender and report to cybercrime.gov.in.",
            'MEDIUM': "⚠️ Exercise extreme caution. Verify independently through official channels.",
            'LOW': "ℹ️ Be cautious. Some suspicious elements detected. Do not share personal data.",
            'SAFE': "✅ No major threats detected. Always stay alert to unsolicited messages."
        }
        return recs.get(risk, recs['SAFE'])

    def _get_url_recommendation(self, score: int) -> str:
        if score >= 70:
            return "🚨 Do NOT visit this site. It's likely a phishing or fraud website."
        elif score >= 40:
            return "⚠️ Proceed with extreme caution. Verify this URL before entering any data."
        else:
            return "✅ URL appears relatively safe, but always verify official domains."


# ═══════════════════════════════════════════════════════
# CLASS: UserManager
# Handles user registration, profile, and XP system
# ═══════════════════════════════════════════════════════

class UserManager:
    """Manages user accounts, profiles, and gamification."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def register(self, name: str, email: str, password: str,
                 age_group: str, vulnerability_group: str) -> dict:
        """Register a new user."""
        # Hash password
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

        # Check duplicate email
        existing = self.db.execute_query(
            "SELECT id FROM users WHERE email = %s", (email,), fetchone=True
        )
        if existing:
            return {'success': False, 'error': 'Email already registered'}

        user_id = self.db.execute_insert(
            """INSERT INTO users (name, email, password_hash, age_group, vulnerability_group,
               xp_points, level, created_at)
               VALUES (%s, %s, %s, %s, %s, 0, 1, NOW())""",
            (name, email, pwd_hash, age_group, vulnerability_group)
        )
        return {'success': True, 'user_id': user_id, 'message': 'Registration successful'}

    def login(self, email: str, password: str) -> dict:
        """Authenticate user."""
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        user = self.db.execute_query(
            "SELECT id, name, email, xp_points, level, vulnerability_group FROM users WHERE email=%s AND password_hash=%s",
            (email, pwd_hash), fetchone=True
        )
        if user:
            return {'success': True, 'user': user}
        return {'success': False, 'error': 'Invalid credentials'}

    def add_xp(self, user_id: int, points: int, reason: str):
        """Award XP to a user."""
        self.db.execute_query(
            "UPDATE users SET xp_points = xp_points + %s WHERE id = %s",
            (points, user_id)
        )
        # Auto level-up every 200 XP
        user = self.db.execute_query(
            "SELECT xp_points FROM users WHERE id = %s", (user_id,), fetchone=True
        )
        if user:
            new_level = (user['xp_points'] // 200) + 1
            self.db.execute_query(
                "UPDATE users SET level = %s WHERE id = %s", (new_level, user_id)
            )
        # Log XP event
        self.db.execute_insert(
            "INSERT INTO xp_log (user_id, points, reason, created_at) VALUES (%s,%s,%s,NOW())",
            (user_id, points, reason)
        )

    def get_profile(self, user_id: int) -> dict:
        """Fetch full user profile."""
        return self.db.execute_query(
            "SELECT * FROM users WHERE id = %s", (user_id,), fetchone=True
        )


# ═══════════════════════════════════════════════════════
# CLASS: ThreatLogger
# Logs all detected threats to the database
# ═══════════════════════════════════════════════════════

class ThreatLogger:
    """Records all threat events for audit and analytics."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def log_threat(self, user_id: int, threat_type: str, content: str,
                   risk_score: int, risk_level: str, action_taken: str,
                   source_ip: str = None) -> int:
        """Log a threat event to the database."""
        return self.db.execute_insert(
            """INSERT INTO threat_logs
               (user_id, threat_type, content_snippet, risk_score, risk_level,
                action_taken, source_ip, detected_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
            (user_id, threat_type, content[:500], risk_score, risk_level,
             action_taken, source_ip)
        )

    def get_recent_threats(self, user_id: int, limit: int = 20) -> list:
        """Fetch recent threat logs for a user."""
        return self.db.execute_query(
            """SELECT * FROM threat_logs WHERE user_id = %s
               ORDER BY detected_at DESC LIMIT %s""",
            (user_id, limit)
        )

    def get_stats(self) -> dict:
        """Aggregate threat statistics."""
        total = self.db.execute_query("SELECT COUNT(*) as cnt FROM threat_logs", fetchone=True)
        blocked = self.db.execute_query("SELECT COUNT(*) as cnt FROM threat_logs WHERE risk_level='HIGH'", fetchone=True)
        return {
            'total_threats': total['cnt'] if total else 0,
            'blocked': blocked['cnt'] if blocked else 0
        }


# ═══════════════════════════════════════════════════════
# CLASS: LearningModule
# Manages educational content and quiz system
# ═══════════════════════════════════════════════════════

class LearningModule:
    """Manages micro-learning content, quizzes, and progress tracking."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_modules(self, vulnerability_group: str = None) -> list:
        """Fetch learning modules, optionally filtered by group."""
        if vulnerability_group:
            return self.db.execute_query(
                """SELECT * FROM learning_modules
                   WHERE target_group = %s OR target_group = 'all'
                   ORDER BY difficulty_level""",
                (vulnerability_group,)
            )
        return self.db.execute_query(
            "SELECT * FROM learning_modules ORDER BY difficulty_level"
        )

    def get_user_progress(self, user_id: int) -> list:
        """Get module completion progress for a user."""
        return self.db.execute_query(
            """SELECT lm.title, lm.category, lp.progress_pct, lp.completed, lp.xp_earned
               FROM learning_progress lp
               JOIN learning_modules lm ON lm.id = lp.module_id
               WHERE lp.user_id = %s""",
            (user_id,)
        )

    def update_progress(self, user_id: int, module_id: int, progress: int):
        """Update module completion progress."""
        existing = self.db.execute_query(
            "SELECT id FROM learning_progress WHERE user_id=%s AND module_id=%s",
            (user_id, module_id), fetchone=True
        )
        completed = 1 if progress >= 100 else 0
        if existing:
            self.db.execute_query(
                "UPDATE learning_progress SET progress_pct=%s, completed=%s WHERE user_id=%s AND module_id=%s",
                (progress, completed, user_id, module_id)
            )
        else:
            self.db.execute_insert(
                "INSERT INTO learning_progress (user_id,module_id,progress_pct,completed) VALUES(%s,%s,%s,%s)",
                (user_id, module_id, progress, completed)
            )

    def submit_quiz(self, user_id: int, module_id: int, score: int, max_score: int) -> dict:
        """Save quiz result and award XP."""
        xp = int((score / max_score) * 80)
        self.db.execute_insert(
            """INSERT INTO quiz_results (user_id, module_id, score, max_score, xp_earned, taken_at)
               VALUES (%s, %s, %s, %s, %s, NOW())""",
            (user_id, module_id, score, max_score, xp)
        )
        return {'xp_earned': xp, 'pass': score >= (max_score * 0.6)}


# ═══════════════════════════════════════════════════════
# CLASS: URLChecker
# Checks and caches URL threat assessments
# ═══════════════════════════════════════════════════════

class URLChecker:
    """Checks URLs and maintains a local threat database."""

    def __init__(self, db_manager: DatabaseManager, analyzer: ThreatAnalyzer):
        self.db = db_manager
        self.analyzer = analyzer

    def check_url(self, url: str, user_id: int) -> dict:
        """Check URL against DB cache first, then run analysis."""
        # Check cache (24-hour validity)
        cached = self.db.execute_query(
            """SELECT * FROM url_checks WHERE url = %s
               AND checked_at > NOW() - INTERVAL 1 DAY""",
            (url,), fetchone=True
        )
        if cached:
            return {
                'from_cache': True,
                'url': url,
                'risk_score': cached['risk_score'],
                'risk_level': cached['risk_level'],
                'threat_type': cached['threat_type'],
                'ssl': bool(cached['ssl_valid']),
            }

        # Run fresh analysis
        result = self.analyzer.analyze_url(url)

        # Save to DB
        self.db.execute_insert(
            """INSERT INTO url_checks (url, user_id, risk_score, risk_level, threat_type,
               ssl_valid, domain_age_days, flags, checked_at)
               VALUES (%s, %s, %s, %s, %s, %s, NULL, %s, NOW())""",
            (url, user_id, result['score'], result['risk_level'],
             ','.join(result.get('flags', [])), result.get('ssl', False),
             json.dumps(result.get('flags', [])))
        )

        return {'from_cache': False, 'url': url, **result}


# ═══════════════════════════════════════════════════════
# INSTANTIATE CLASSES
# ═══════════════════════════════════════════════════════

analyzer = ThreatAnalyzer()
user_mgr = UserManager(db)
threat_logger = ThreatLogger(db)
learning = LearningModule(db)
url_checker = URLChecker(db, analyzer)


# ═══════════════════════════════════════════════════════
# FLASK API ROUTES
# ═══════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan/message', methods=['POST'])
def scan_message():
    """POST /api/scan/message — Analyze a message for threats."""
    data = request.json
    text = data.get('text', '')
    user_id = data.get('user_id', 1)

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    result = analyzer.analyze_text(text)

    # Log to DB
    if result['is_threat']:
        threat_logger.log_threat(
            user_id=user_id,
            threat_type=','.join(result['threat_types']) if result['threat_types'] else 'suspicious',
            content=text,
            risk_score=result['score'],
            risk_level=result['risk_level'],
            action_taken='blocked' if result['risk_level'] == 'HIGH' else 'warned',
            source_ip=request.remote_addr
        )

    return jsonify({'status': 'success', 'analysis': result})


@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """POST /api/scan/url — Check a URL for phishing/fraud."""
    data = request.json
    url = data.get('url', '')
    user_id = data.get('user_id', 1)

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = url_checker.check_url(url, user_id)
    return jsonify({'status': 'success', 'result': result})


@app.route('/api/users/register', methods=['POST'])
def register():
    """POST /api/users/register — Register a new user."""
    data = request.json
    result = user_mgr.register(
        name=data.get('name', ''),
        email=data.get('email', ''),
        password=data.get('password', ''),
        age_group=data.get('age_group', 'adult'),
        vulnerability_group=data.get('vulnerability_group', 'general')
    )
    return jsonify(result)


@app.route('/api/users/login', methods=['POST'])
def login():
    """POST /api/users/login — Authenticate a user."""
    data = request.json
    result = user_mgr.login(data.get('email', ''), data.get('password', ''))
    return jsonify(result)


@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile(user_id):
    """GET /api/users/<id>/profile — Fetch user profile."""
    profile = user_mgr.get_profile(user_id)
    if not profile:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(profile)


@app.route('/api/threats/recent', methods=['GET'])
def recent_threats():
    """GET /api/threats/recent — Get recent threat events."""
    user_id = request.args.get('user_id', 1, type=int)
    threats = threat_logger.get_recent_threats(user_id)
    return jsonify({'threats': threats})


@app.route('/api/threats/stats', methods=['GET'])
def threat_stats():
    """GET /api/threats/stats — Aggregate statistics."""
    stats = threat_logger.get_stats()
    return jsonify(stats)


@app.route('/api/learning/modules', methods=['GET'])
def get_modules():
    """GET /api/learning/modules — Fetch learning modules."""
    group = request.args.get('group', None)
    modules = learning.get_modules(group)
    return jsonify({'modules': modules})


@app.route('/api/learning/progress', methods=['POST'])
def update_progress():
    """POST /api/learning/progress — Update module progress."""
    data = request.json
    learning.update_progress(
        user_id=data.get('user_id'),
        module_id=data.get('module_id'),
        progress=data.get('progress', 0)
    )
    return jsonify({'status': 'updated'})


@app.route('/api/quiz/submit', methods=['POST'])
def submit_quiz():
    """POST /api/quiz/submit — Submit quiz answers and earn XP."""
    data = request.json
    user_id = data.get('user_id')
    module_id = data.get('module_id')
    score = data.get('score', 0)
    max_score = data.get('max_score', 5)

    result = learning.submit_quiz(user_id, module_id, score, max_score)
    if result['xp_earned'] > 0:
        user_mgr.add_xp(user_id, result['xp_earned'], f"Quiz completion — module {module_id}")

    return jsonify({'status': 'success', 'result': result})


@app.route('/api/dashboard/summary', methods=['GET'])
def dashboard_summary():
    """GET /api/dashboard/summary — Full dashboard data."""
    user_id = request.args.get('user_id', 1, type=int)
    profile = user_mgr.get_profile(user_id)
    stats = threat_logger.get_stats()
    recent = threat_logger.get_recent_threats(user_id, limit=5)
    progress = learning.get_user_progress(user_id)

    return jsonify({
        'user': profile,
        'stats': stats,
        'recent_threats': recent,
        'learning_progress': progress
    })


# ═══════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════

if __name__ == '__main__':
    print("ShieldAI Backend starting on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
