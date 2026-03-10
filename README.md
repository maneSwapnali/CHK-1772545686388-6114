# ShieldNet — AI Digital Safety & Citizen Protection Tool

## Setup & Run

### 1. Install Dependencies
```bash
pip install flask
```
OR
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
cd digital-safety-tool
python app.py
```

### 3. Open in Browser
```
http://localhost:5000
```

---

## Default Admin Login
- **Username:** `admin`
- **Password:** `admin123`

---

## Folder Structure
```
digital-safety-tool/
├── app.py                  # Flask backend (main server)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── database/
│   └── safety_tool.db      # SQLite database (auto-created)
├── templates/
│   └── index.html          # Single-page application (all pages)
└── static/
    ├── css/                # (optional custom CSS)
    └── js/                 # (optional custom JS)
```

---

## Database Schema

### users
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| username | TEXT UNIQUE | Login username |
| email | TEXT UNIQUE | User email |
| password | TEXT | SHA-256 hashed |
| role | TEXT | 'user' or 'admin' |
| created_at | TIMESTAMP | Registration date |

### scam_reports
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Reports user |
| report_type | TEXT | url/message/email/other |
| content | TEXT | The suspicious content |
| description | TEXT | Additional context |
| risk_level | TEXT | low/medium/high/critical |
| status | TEXT | pending/reviewed/dismissed |
| created_at | TIMESTAMP | Submission date |

### url_checks
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Who checked |
| url | TEXT | The URL checked |
| result | TEXT | SAFE/SUSPICIOUS/DANGEROUS |
| risk_score | INTEGER | 0-100 |
| checked_at | TIMESTAMP | Check time |

### message_checks
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | Who checked |
| message_preview | TEXT | First 100 chars |
| result | TEXT | SAFE/SUSPICIOUS/SCAM |
| keywords_found | TEXT | Comma-separated keywords |
| risk_score | INTEGER | 0-100 |
| checked_at | TIMESTAMP | Check time |

---

## AI Analysis Engine

### URL Scanner
- Pattern matching against 15+ suspicious URL patterns
- Typosquatting detection (paypa1, amaz0n, g00gle)
- IP-based URL detection
- HTTPS verification
- URL length analysis
- Multi-subdomain detection
- Known safe domain whitelist

### Scam Text Detector
- 4-tier keyword classification:
  - **Critical** (30pts each): "verify your account immediately", "wire transfer", etc.
  - **High** (15pts each): "bank account", "social security", "lottery winner", etc.
  - **Medium** (8pts each): "click here", "guaranteed", "earn money fast", etc.
  - **Low** (3pts each): "free", "prize", "win", "discount", etc.
- Urgency pattern detection (regex)
- Embedded URL detection in messages
- Risk scoring: 0-100
  - 0-9: Safe
  - 10-29: Low Risk
  - 30-59: Suspicious
  - 60+: Scam

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register | User registration |
| POST | /api/login | User login |
| POST | /api/logout | User logout |
| GET | /api/session | Check current session |
| POST | /api/check-url | Scan a URL |
| POST | /api/check-message | Analyze message text |
| POST | /api/submit-report | Submit scam report |
| GET | /api/admin/stats | Admin statistics |
| GET | /api/admin/users | List all users |
| GET | /api/admin/reports | List all reports |
| PUT | /api/admin/report/<id>/status | Update report status |

---

## Features
1. **Home Page** — Digital safety introduction with live stats
2. **User Auth** — Login/registration with SHA-256 password hashing
3. **URL Safety Checker** — Pattern-based malicious URL detection
4. **Scam Detector** — Multi-tier keyword AI analysis for messages/emails
5. **Report System** — Community threat reporting stored in SQLite
6. **Cyber Safety Academy** — 12 essential cyber safety tips
7. **Admin Dashboard** — User management, report review, statistics
