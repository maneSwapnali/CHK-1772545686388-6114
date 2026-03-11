-- ═══════════════════════════════════════════════════
-- ShieldAI — MySQL Database Schema
-- File: schema.sql
-- Run: mysql -u root -p < schema.sql
-- ═══════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS shieldai_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE shieldai_db;

-- ── TABLE: users ──────────────────────────────────────
-- Stores user accounts and profile data
CREATE DATABASE IF NOT EXISTS shieldai_db;
USE shieldai_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    phone VARCHAR(20),
    age_group ENUM('child','teen','adult','senior') DEFAULT 'adult',
    vulnerability_group ENUM('general','senior','rural','teenager','low_literacy') DEFAULT 'general',
    xp_points INT DEFAULT 0,
    level INT DEFAULT 1,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- ── TABLE: threat_logs ────────────────────────────────
-- Every detected threat event is recorded here
CREATE TABLE threat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    threat_type VARCHAR(100),
    content_snippet TEXT,
    risk_score INT,
    risk_level ENUM('SAFE','LOW','MEDIUM','HIGH'),
    action_taken ENUM('blocked','warned','allowed','reported'),
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── TABLE: url_checks ─────────────────────────────────
-- Stores results of URL threat analysis (cached for 24h)
CREATE TABLE IF NOT EXISTS url_checks (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    url             VARCHAR(2000) NOT NULL,
    user_id         INT,
    risk_score      INT DEFAULT 0,
    risk_level      ENUM('SAFE','LOW','MEDIUM','HIGH') DEFAULT 'SAFE',
    threat_type     VARCHAR(200),
    ssl_valid       TINYINT(1) DEFAULT 0,
    domain_age_days INT,
    flags           TEXT,                  -- JSON array of flags
    checked_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_url (url(255)),
    INDEX idx_checked_at (checked_at)
);

-- ── TABLE: learning_modules ───────────────────────────
-- Micro-learning content library
CREATE TABLE IF NOT EXISTS learning_modules (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    title           VARCHAR(200) NOT NULL,
    category        ENUM('phishing','fraud','malware','misinformation','social_engineering','general') DEFAULT 'general',
    description     TEXT,
    content         LONGTEXT,              -- HTML or markdown content
    duration_mins   INT DEFAULT 5,
    difficulty_level ENUM('beginner','intermediate','advanced') DEFAULT 'beginner',
    target_group    VARCHAR(100) DEFAULT 'all',
    xp_reward       INT DEFAULT 40,
    is_active       TINYINT(1) DEFAULT 1,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_target (target_group)
);

-- ── TABLE: learning_progress ──────────────────────────
-- Per-user module completion tracking
CREATE TABLE IF NOT EXISTS learning_progress (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    module_id       INT NOT NULL,
    progress_pct    INT DEFAULT 0,         -- 0-100
    completed       TINYINT(1) DEFAULT 0,
    xp_earned       INT DEFAULT 0,
    started_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at    DATETIME,
    UNIQUE KEY uq_user_module (user_id, module_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES learning_modules(id) ON DELETE CASCADE
);

-- ── TABLE: quiz_results ───────────────────────────────
-- Stores every quiz attempt and score
CREATE TABLE IF NOT EXISTS quiz_results (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    module_id       INT NOT NULL,
    score           INT DEFAULT 0,
    max_score       INT DEFAULT 5,
    xp_earned       INT DEFAULT 0,
    passed          TINYINT(1) GENERATED ALWAYS AS (score >= (max_score * 0.6)) STORED,
    taken_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES learning_modules(id) ON DELETE CASCADE,
    INDEX idx_user_quiz (user_id)
);

-- ── TABLE: xp_log ─────────────────────────────────────
-- Audit trail of all XP awarded
CREATE TABLE IF NOT EXISTS xp_log (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    points      INT NOT NULL,
    reason      VARCHAR(255),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── TABLE: scam_patterns ──────────────────────────────
-- Admin-maintained database of known scam patterns
CREATE TABLE IF NOT EXISTS scam_patterns (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    pattern_text    VARCHAR(500) NOT NULL,
    pattern_type    ENUM('keyword','regex','domain','phone') DEFAULT 'keyword',
    threat_category VARCHAR(100),
    risk_weight     INT DEFAULT 10,        -- contribution to risk score
    is_active       TINYINT(1) DEFAULT 1,
    added_by        VARCHAR(100) DEFAULT 'system',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pattern_type (pattern_type),
    INDEX idx_active (is_active)
);

-- ── TABLE: reports ────────────────────────────────────
-- User-submitted scam reports
CREATE TABLE IF NOT EXISTS reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT,
    report_type     ENUM('phishing','fraud','malware','misinformation','other') DEFAULT 'other',
    description     TEXT,
    evidence_url    VARCHAR(2000),
    status          ENUM('pending','reviewed','resolved','rejected') DEFAULT 'pending',
    submitted_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_status (status)
);

-- ── TABLE: alerts ─────────────────────────────────────
-- System-wide threat alerts shown to users
CREATE TABLE IF NOT EXISTS alerts (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    title           VARCHAR(300) NOT NULL,
    body            TEXT,
    severity        ENUM('info','warning','critical') DEFAULT 'warning',
    target_group    VARCHAR(100) DEFAULT 'all',
    is_active       TINYINT(1) DEFAULT 1,
    expires_at      DATETIME,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_active_alert (is_active, expires_at)
);

-- ═══════════════════════════════════════════════════
-- SEED DATA
-- ═══════════════════════════════════════════════════

-- Demo user
INSERT INTO users (name, email, password_hash, age_group, vulnerability_group, xp_points, level)
VALUES ('Ravi Kumar', 'ravi@example.com',
        SHA2('password123', 256), 'adult', 'general', 340, 4);

-- Learning modules
INSERT INTO learning_modules (title, category, description, duration_mins, difficulty_level, target_group, xp_reward) VALUES
('How Phishing Works', 'phishing', 'Understand how attackers steal credentials via fake sites and emails', 5, 'beginner', 'all', 40),
('Spotting Fake Websites', 'phishing', 'Learn to identify fraudulent websites before entering data', 7, 'beginner', 'all', 40),
('OTP & Banking Frauds', 'fraud', 'How criminals steal money using OTP manipulation tactics', 6, 'intermediate', 'all', 60),
('Investment Scam Tactics', 'fraud', 'Recognize Ponzi schemes, crypto scams, and fake high-return offers', 8, 'intermediate', 'all', 60),
('Misinformation & Deepfakes', 'misinformation', 'Identify AI-generated fake content and viral health misinformation', 10, 'advanced', 'all', 80),
('Senior Citizen Online Safety', 'social_engineering', 'Special guide for senior citizens — phone and online scam protection', 8, 'beginner', 'senior', 40),
('WhatsApp Scam Awareness', 'fraud', 'Recognize scam links, prize frauds, and fake jobs on WhatsApp', 5, 'beginner', 'all', 40);

-- Known scam patterns
INSERT INTO scam_patterns (pattern_text, pattern_type, threat_category, risk_weight) VALUES
('you have won', 'keyword', 'lottery_fraud', 35),
('otp', 'keyword', 'phishing', 25),
('guaranteed returns', 'keyword', 'investment_scam', 35),
('hdfcsecure-login', 'domain', 'phishing', 50),
('paytm-reward', 'domain', 'phishing', 50),
('free-prize', 'domain', 'fraud', 40),
('sbi-netbanking\\.(?!sbi)', 'regex', 'phishing', 45);

-- Active alert
INSERT INTO alerts (title, body, severity, target_group)
VALUES ('SBI Phishing Campaign Active',
        'A new phishing campaign impersonating SBI Bank is circulating via SMS. 247 users alerted.',
        'critical', 'all');

COMMIT;
