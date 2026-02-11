#!/bin/bash

################################################################################
#
# BOT DETECTION PLATFORM - AWS LIGHTSAIL INSTALLER
# Optimized untuk AWS Lightsail Ubuntu 22.04
# Version: 1.0
#
# PERLU DIUBAH?
#   Tidak. Script sudah diset untuk AWS Lightsail (user ubuntu, path /home/ubuntu).
#   IP dideteksi otomatis; email & domain ditanya saat instalasi.
#   Hanya ubah jika VPS Anda pakai user lain (bukan ubuntu) atau path lain.
#
# CUKUP UPLOAD SCRIPT INI SAJA?
#   Ya. Cukup upload file install-botdetection.sh ke VPS. Script ini lengkap:
#   semua file (backend, SDK, config) dibuat otomatis di dalam script.
#   Tidak perlu upload folder backend/ atau repo lainnya.
#
# CARA PAKAI:
# 1. SSH ke instance Lightsail (user ubuntu).
# 2. Upload script ke /home/ubuntu/ (SCP/PuTTY SFTP) atau paste isi via nano.
# 3. chmod +x install-botdetection.sh
# 4. sudo ./install-botdetection.sh
# 5. Isi email, domain (opsional), konfirmasi y.
#
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables - TIDAK PERLU DIUBAH
PROJECT_NAME="bot-detection-platform"
PROJECT_DIR="/home/ubuntu/$PROJECT_NAME"
DOMAIN=""
EMAIL=""

print_header() {
    echo ""
    echo "========================================================================"
    echo -e "${BLUE}$1${NC}"
    echo "========================================================================"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

################################################################################
# Welcome
################################################################################

welcome() {
    clear
    print_header "🤖 BOT DETECTION PLATFORM - AWS LIGHTSAIL INSTALLER"
    
    cat << "EOF"
    ____        __     ____       __            __            
   / __ )____  / /_   / __ \___  / /____  _____/ /_____  _____
  / __  / __ \/ __/  / / / / _ \/ __/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / /_/ / /_   / /_/ /  __/ /_/  __/ /__/ /_/ /_/ / /    
/_____/\____/\__/  /_____/\___/\__/\___/\___/\__/\____/_/     
                                                               
         AWS Lightsail Edition - Ready to Install
EOF
    
    echo ""
    echo "This installer will automatically setup:"
    echo "  • PostgreSQL Database"
    echo "  • Redis Cache"
    echo "  • Python Flask API"
    echo "  • Nginx Web Server"
    echo "  • Free Threat Intelligence Feeds"
    echo "  • JavaScript SDK"
    echo ""
    
    # Get Lightsail IP automatically
    LIGHTSAIL_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)
    
    echo "Detected IP: $LIGHTSAIL_IP"
    echo ""
    
    read -p "Enter your email (for notifications): " EMAIL
    read -p "Enter domain name (optional, press ENTER to skip): " DOMAIN
    
    if [ -z "$EMAIL" ]; then
        EMAIL="admin@localhost"
    fi
    
    echo ""
    print_info "Configuration:"
    echo "  Lightsail IP: $LIGHTSAIL_IP"
    echo "  Email: $EMAIL"
    echo "  Domain: ${DOMAIN:-Will use IP address}"
    echo ""
    
    read -p "Start installation? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Installation cancelled."
        exit 1
    fi
}

################################################################################
# Step 1: Install Dependencies
################################################################################

install_dependencies() {
    print_header "Step 1/12: Installing System Dependencies"
    
    print_info "Updating package lists..."
    sudo apt update -qq
    
    print_info "Upgrading system packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    print_info "Installing required packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        curl wget git vim ufw \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        redis-server nginx \
        certbot python3-certbot-nginx \
        jq htop net-tools unzip
    
    print_success "System dependencies installed"
}

################################################################################
# Step 2: Firewall
################################################################################

setup_firewall() {
    print_header "Step 2/12: Configuring Firewall"
    
    print_info "Setting up UFW firewall..."
    
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 22/tcp comment 'SSH'
    sudo ufw allow 80/tcp comment 'HTTP'
    sudo ufw allow 443/tcp comment 'HTTPS'
    echo "y" | sudo ufw enable
    
    print_success "Firewall configured"
    print_info "Remember: Also check Lightsail firewall in console!"
}

################################################################################
# Step 3: Directories
################################################################################

setup_directories() {
    print_header "Step 3/12: Creating Project Directories"
    
    mkdir -p "$PROJECT_DIR"/{backend,sdk,scripts,nginx,logs}
    mkdir -p "$PROJECT_DIR/backend/data"
    
    print_success "Directories created"
}

################################################################################
# Step 4: PostgreSQL
################################################################################

setup_postgresql() {
    print_header "Step 4/12: Setting Up PostgreSQL"
    
    DB_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-25)
    
    print_info "Creating database..."
    
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS botdetection;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP USER IF EXISTS botuser;" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE botdetection;"
    sudo -u postgres psql -c "CREATE USER botuser WITH PASSWORD '$DB_PASSWORD';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE botdetection TO botuser;"
    sudo -u postgres psql -c "ALTER DATABASE botdetection OWNER TO botuser;"
    
    echo "DATABASE_URL=postgresql://botuser:$DB_PASSWORD@localhost/botdetection" > "$PROJECT_DIR/backend/.env"
    
    print_success "PostgreSQL configured"
}

################################################################################
# Step 5: Redis
################################################################################

setup_redis() {
    print_header "Step 5/12: Setting Up Redis"
    
    print_info "Configuring Redis..."
    
    sudo sed -i 's/# maxmemory <bytes>/maxmemory 128mb/' /etc/redis/redis.conf
    sudo sed -i 's/# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
    
    sudo systemctl restart redis-server
    sudo systemctl enable redis-server
    
    echo "REDIS_HOST=localhost" >> "$PROJECT_DIR/backend/.env"
    echo "REDIS_PORT=6379" >> "$PROJECT_DIR/backend/.env"
    
    print_success "Redis configured"
}

################################################################################
# Step 6: Backend Files
################################################################################

create_backend_files() {
    print_header "Step 6/12: Creating Backend Application"
    
    SECRET_KEY=$(openssl rand -base64 32)
    echo "SECRET_KEY=$SECRET_KEY" >> "$PROJECT_DIR/backend/.env"
    echo "FLASK_ENV=production" >> "$PROJECT_DIR/backend/.env"
    echo "PROXY_CHECK_ENABLED=true" >> "$PROJECT_DIR/backend/.env"
    
    print_info "Creating requirements.txt..."
    cat > "$PROJECT_DIR/backend/requirements.txt" << 'EOF'
Flask==3.0.0
Flask-CORS==4.0.0
Flask-SQLAlchemy==3.1.1
psycopg2-binary==2.9.9
redis==5.0.1
requests==2.31.0
user-agents==2.2.0
python-dotenv==1.0.0
gunicorn==21.2.0
EOF
    
    print_info "Creating app.py..."
    cat > "$PROJECT_DIR/backend/app.py" << 'EOFAPP'
from flask import (
    Flask,
    request,
    jsonify,
    render_template_string,
    redirect,
    url_for,
    session,
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime, timedelta
import hashlib
import secrets
import redis
import json
import os
from dotenv import load_dotenv
from user_agents import parse as parse_ua
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

# ---------------------------------------------------------------------------
# Bobot skor (0–1 per kategori, total = 1.0)
# Ubah di sini untuk menyesuaikan prioritas deteksi
# ---------------------------------------------------------------------------
SCORE_WEIGHTS = {
    'ip': 0.30,        # IP reputation + proxy/VPN
    'ua': 0.25,        # User-Agent / bot signature
    'behavior': 0.20,  # Mouse, time on page, canvas
    'fingerprint': 0.15,
    'velocity': 0.10,
}

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Auth & role
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    # Trial management
    trial_expires_at = db.Column(db.DateTime, nullable=True)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), default='Default Key')
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    requests_per_hour = db.Column(db.Integer, default=1000)
    requests_per_day = db.Column(db.Integer, default=10000)
    # Expiry & regenerate limits
    expires_at = db.Column(db.DateTime, nullable=True)
    regenerate_count = db.Column(db.Integer, default=0)
    is_trial = db.Column(db.Boolean, default=False)

class DetectionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    is_bot = db.Column(db.Boolean)
    fraud_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    reasons = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# Detection Engine (dengan proxy/VPN check + bobot skor)
# ---------------------------------------------------------------------------

class DetectionEngine:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.data_dir = os.path.join(os.path.dirname(__file__), 'data')
        self.weights = SCORE_WEIGHTS
        # Free API: 45 req/min. Cache 24 jam.
        self.proxy_check_enabled = os.getenv('PROXY_CHECK_ENABLED', 'true').lower() == 'true'

    def analyze(self, ip, user_agent, headers, client_data):
        raw_scores = {}

        ip_score, ip_reasons = self._check_ip(ip)
        raw_scores['ip'] = min(100, ip_score)

        ua_score, ua_reasons = self._check_ua(user_agent)
        raw_scores['ua'] = min(100, ua_score)

        behavior_score, behavior_reasons = self._check_behavior(client_data)
        raw_scores['behavior'] = min(100, behavior_score)

        fingerprint = self._fingerprint(client_data)
        fp_score, fp_reasons = self._check_fingerprint(fingerprint)
        raw_scores['fingerprint'] = min(100, fp_score)

        velocity_score, velocity_reasons = self._check_velocity(ip)
        raw_scores['velocity'] = min(100, velocity_score)

        # Skor akhir = bobot tertimbang (0–100)
        final_score = 0
        for key, weight in self.weights.items():
            final_score += weight * raw_scores.get(key, 0)
        final_score = round(min(100, final_score))

        reasons = list(set(
            ip_reasons + ua_reasons + behavior_reasons + fp_reasons + velocity_reasons
        ))

        is_bot = final_score >= 50
        risk = "high" if final_score >= 70 else "medium" if final_score >= 40 else "low"

        return {
            "bot_detected": is_bot,
            "fraud_score": final_score,
            "risk_level": risk,
            "reasons": reasons,
            "ip_address": ip,
            "fingerprint": fingerprint,
            "score_breakdown": {
                "ip": raw_scores['ip'],
                "user_agent": raw_scores['ua'],
                "behavior": raw_scores['behavior'],
                "fingerprint": raw_scores['fingerprint'],
                "velocity": raw_scores['velocity'],
            },
            "timestamp": datetime.now().isoformat()
        }

    def _check_ip(self, ip):
        score, reasons = 0, []

        # Skip proxy API untuk IP private/lokal
        if self._is_private_ip(ip):
            return 0, []

        cache_key = f"ip:{ip}"
        cached = self.redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return data['score'], data['reasons']

        # 1) Blocklists
        for fname in ['feodo_blocklist.txt', 'emerging_threats.txt', 'tor_exit_nodes.txt']:
            fpath = os.path.join(self.data_dir, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    if ip in f.read():
                        score += 60
                        reasons.append(f"ip_in_{fname.replace('.txt', '')}")
                        break

        # 2) Datacenter / prefix sederhana
        if any(ip.startswith(p) for p in ['45.', '104.', '138.', '167.', '192.0.2.']):
            score += 15
            reasons.append("datacenter_ip")

        # 3) Proxy/VPN check (ip-api.com, free, no key)
        if self.proxy_check_enabled:
            proxy_score, proxy_reasons = self._check_proxy_vpn(ip)
            score += proxy_score
            reasons.extend(proxy_reasons)

        score = min(100, score)
        self.redis.setex(cache_key, 3600, json.dumps({'score': score, 'reasons': reasons}))
        return score, reasons

    def _is_private_ip(self, ip):
        if not ip or ip == '127.0.0.1':
            return True
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        try:
            a, b, c, d = (int(x) for x in parts)
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
        except ValueError:
            pass
        return False

    def _check_proxy_vpn(self, ip):
        cache_key = f"ipmeta:{ip}"
        cached = self.redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return data.get('score', 0), data.get('reasons', [])

        score, reasons = 0, []
        try:
            # ip-api.com: free, 45 req/min. Fields: proxy, hosting.
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=proxy,hosting",
                timeout=3
            )
            if r.status_code != 200:
                self.redis.setex(cache_key, 3600, json.dumps({'score': 0, 'reasons': []}))
                return 0, []

            data = r.json()
            if data.get('proxy'):
                score += 50
                reasons.append("proxy_detected")
            if data.get('hosting'):
                score += 30
                reasons.append("hosting_datacenter")

            result = {'score': min(80, score), 'reasons': reasons}
            self.redis.setex(cache_key, 86400, json.dumps(result))  # 24h cache
            return result['score'], result['reasons']
        except Exception:
            self.redis.setex(cache_key, 300, json.dumps({'score': 0, 'reasons': []}))
            return 0, []

    def _check_ua(self, ua_string):
        if not ua_string or len(ua_string) < 10:
            return 40, ["missing_user_agent"]

        score, reasons = 0, []
        try:
            ua = parse_ua(ua_string)
        except Exception:
            return 35, ["invalid_user_agent"]

        if ua.is_bot:
            score += 50
            reasons.append("bot_user_agent")

        keywords = ['selenium', 'puppeteer', 'headless', 'bot', 'crawler', 'scrapy', 'phantom']
        if any(k in ua_string.lower() for k in keywords):
            score += 45
            reasons.append("automation_detected")

        return min(100, score), reasons

    def _check_behavior(self, data):
        score, reasons = 0, []

        if data.get('mouse_events', 0) < 3:
            score += 30
            reasons.append("no_mouse_movement")

        if data.get('time_on_page', 0) < 0.5:
            score += 25
            reasons.append("too_fast")

        if not data.get('canvas_hash'):
            score += 20
            reasons.append("no_canvas")

        return min(100, score), reasons

    def _fingerprint(self, data):
        fp = f"{data.get('screen_resolution','')}{data.get('timezone','')}{data.get('canvas_hash','')}"
        return hashlib.sha256(fp.encode()).hexdigest()[:16]

    def _check_fingerprint(self, fp):
        key = f"fp:{fp}"
        count = self.redis.incr(key)
        self.redis.expire(key, 3600)

        if count > 50:
            return 40, ["fingerprint_abuse"]
        return 0, []

    def _check_velocity(self, ip):
        key = f"vel:{ip}"
        count = self.redis.incr(key)
        self.redis.expire(key, 60)

        if count > 30:
            return 35, ["high_velocity"]
        return 0, []


detector = DetectionEngine(redis_client)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return redirect(url_for('dashboard'))
        return view_func(*args, **kwargs)

    return wrapped


def verify_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return None, {"error": "API key required"}, 401

    key_obj = APIKey.query.filter_by(key=api_key, active=True).first()
    if not key_obj:
        return None, {"error": "Invalid API key"}, 401

    # Check expiry (trial or paid)
    if key_obj.expires_at and datetime.utcnow() > key_obj.expires_at:
        return None, {"error": "API key expired"}, 403

    if not check_rate_limit(key_obj):
        return None, {"error": "Rate limit exceeded"}, 429

    return key_obj, None, None


def check_rate_limit(key_obj):
    hour_key = f"rl:{key_obj.key}:h:{datetime.now().hour}"
    day_key = f"rl:{key_obj.key}:d:{datetime.now().date()}"

    hour_count = int(redis_client.get(hour_key) or 0)
    day_count = int(redis_client.get(day_key) or 0)

    if hour_count >= key_obj.requests_per_hour or day_count >= key_obj.requests_per_day:
        return False

    pipe = redis_client.pipeline()
    pipe.incr(hour_key)
    pipe.expire(hour_key, 3600)
    pipe.incr(day_key)
    pipe.expire(day_key, 86400)
    pipe.execute()

    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

GLASS_CSS = """
    body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: #e5e7eb;
        background-image: url('https://cdn.pixabay.com/photo/2018/01/25/20/53/lifestyle-3107041_1280.jpg');
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    .nav-bar {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        height: 64px;
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 40;
        pointer-events: none;
    }
    .nav-inner {
        width: 100%;
        max-width: 1120px;
        padding: 10px 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.82);
        border: 1px solid rgba(148, 163, 184, 0.55);
        box-shadow:
          0 18px 40px rgba(15, 23, 42, 0.75),
          0 0 0 1px rgba(15, 23, 42, 0.7);
        backdrop-filter: blur(20px) saturate(150%);
        -webkit-backdrop-filter: blur(20px) saturate(150%);
        pointer-events: auto;
    }
    .brand {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .brand-logo {
        width: 34px;
        height: 34px;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 0 0 1px rgba(148, 163, 184, 0.7);
        background: rgba(15, 23, 42, 0.9);
    }
    .brand-logo img {
        width: 100%;
        height: 100%;
        object-fit: cover;
        display: block;
    }
    .brand-name {
        font-weight: 700;
        font-size: 18px;
        letter-spacing: 0.02em;
        color: #f9fafb;
    }
    .nav-links {
        display: flex;
        gap: 18px;
        font-size: 13px;
        color: #e5e7eb;
    }
    .nav-links span {
        opacity: 0.85;
    }
    .nav-links span:hover {
        opacity: 1;
    }
    .glass-root {
        width: 100%;
        max-width: 1100px;
        padding: 24px;
        display: flex;
        gap: 24px;
        flex-wrap: wrap;
        justify-content: center;
    }
    .glass-card {
        flex: 1 1 320px;
        max-width: 520px;
        background: rgba(15, 23, 42, 0.45);
        border-radius: 28px;
        border: 1px solid rgba(148, 163, 184, 0.45);
        box-shadow:
            0 18px 40px rgba(15, 23, 42, 0.55),
            0 0 0 1px rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(22px) saturate(150%);
        -webkit-backdrop-filter: blur(22px) saturate(150%);
        padding: 24px 28px;
        position: relative;
        overflow: hidden;
    }
    .glass-card::before {
        content: "";
        position: absolute;
        inset: 0;
        background: radial-gradient(circle at top left, rgba(96, 165, 250, 0.35), transparent 55%);
        mix-blend-mode: screen;
        opacity: 0.75;
        pointer-events: none;
    }
    .glass-card-inner {
        position: relative;
        z-index: 1;
    }
    h1, h2 {
        margin: 0 0 12px;
        font-weight: 650;
        letter-spacing: 0.04em;
    }
    h1 span {
        font-weight: 800;
        background: linear-gradient(120deg, #38bdf8, #a855f7, #f97316);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
    }
    p {
        margin: 4px 0;
        color: #e5e7eb;
        font-size: 14px;
    }
    .muted {
        color: #9ca3af;
        font-size: 13px;
    }
    .badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 4px 10px;
        font-size: 11px;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(148, 163, 184, 0.55);
        color: #e5e7eb;
    }
    .badge.success { color: #bbf7d0; border-color: rgba(34, 197, 94, 0.6); }
    .badge.warn { color: #fed7aa; border-color: rgba(248, 180, 0, 0.75); }
    .badge.danger { color: #fecaca; border-color: rgba(248, 113, 113, 0.75); }
    .field {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-top: 14px;
    }
    .field label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #9ca3af;
    }
    .field input, .field select {
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.6);
        padding: 9px 14px;
        font-size: 14px;
        outline: none;
        background: rgba(15, 23, 42, 0.85);
        color: #f9fafb;
    }
    .field input::placeholder {
        color: #6b7280;
    }
    .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        border-radius: 999px;
        border: none;
        padding: 9px 18px;
        margin-top: 16px;
        font-size: 14px;
        font-weight: 600;
        letter-spacing: 0.04em;
        cursor: pointer;
        background: linear-gradient(135deg, #38bdf8, #6366f1);
        color: #f9fafb;
        box-shadow: 0 10px 26px rgba(37, 99, 235, 0.55);
    }
    .btn.secondary {
        background: rgba(15, 23, 42, 0.85);
        box-shadow: none;
        border: 1px solid rgba(148, 163, 184, 0.6);
        color: #e5e7eb;
        margin-left: 8px;
    }
    .btn[disabled] {
        opacity: 0.5;
        cursor: not-allowed;
        box-shadow: none;
    }
    .api-key-box {
        margin-top: 14px;
        padding: 10px 14px;
        border-radius: 14px;
        background: rgba(15, 23, 42, 0.9);
        border: 1px dashed rgba(148, 163, 184, 0.7);
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 13px;
        word-break: break-all;
    }
    .top-nav {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 18px;
    }
    .top-nav a {
        color: #e5e7eb;
        text-decoration: none;
        font-size: 13px;
        opacity: 0.85;
    }
    .top-nav a:hover {
        opacity: 1;
        text-decoration: underline;
    }
"""

@app.route('/api/v1/detect', methods=['POST', 'OPTIONS'])
def detect():
    if request.method == 'OPTIONS':
        return '', 204

    key_obj, err, code = verify_api_key()
    if err:
        return jsonify(err), code

    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')
    data = request.json or {}

    result = detector.analyze(ip, ua, request.headers, data)

    log = DetectionLog(
        api_key_id=key_obj.id,
        ip_address=ip,
        user_agent=ua,
        is_bot=result['bot_detected'],
        fraud_score=result['fraud_score'],
        risk_level=result['risk_level'],
        reasons=result['reasons']
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "request_id": log.id, **result})


@app.route('/api/v1/stats', methods=['GET'])
def stats():
    key_obj, err, code = verify_api_key()
    if err:
        return jsonify(err), code

    total = DetectionLog.query.filter_by(api_key_id=key_obj.id).count()
    bots = DetectionLog.query.filter_by(api_key_id=key_obj.id, is_bot=True).count()
    today = DetectionLog.query.filter(
        DetectionLog.api_key_id == key_obj.id,
        DetectionLog.timestamp >= datetime.now().date()
    ).count()

    recent = DetectionLog.query.filter_by(api_key_id=key_obj.id)\
        .order_by(DetectionLog.timestamp.desc()).limit(20).all()

    return jsonify({
        "total_requests": total,
        "bots_detected": bots,
        "bot_percentage": round((bots/total*100) if total > 0 else 0, 2),
        "today_requests": today,
        "recent": [{
            "ip": r.ip_address,
            "is_bot": r.is_bot,
            "score": r.fraud_score,
            "risk": r.risk_level,
            "reasons": r.reasons,
            "time": r.timestamp.isoformat()
        } for r in recent]
    })


@app.route('/api/v1/create-key', methods=['POST'])
def create_key():
    data = request.json

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        user = User(email=data['email'], name=data.get('name', 'User'))
        db.session.add(user)
        db.session.flush()

    key = APIKey(
        user_id=user.id,
        key=f"VTX-{secrets.token_hex(24)}",
        name=data.get('key_name', 'API Key'),
        is_trial=False,           # API created via raw endpoint is non-trial
        expires_at=None
    )
    db.session.add(key)
    db.session.commit()

    return jsonify({"success": True, "api_key": key.key})


@app.route('/api/v1/health')
def health():
    try:
        db.session.execute(text("SELECT 1"))
        redis_client.ping()
        return jsonify({"status": "healthy", "db": "ok", "redis": "ok"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@app.route('/')
def index():
    # If already logged in, go straight to dashboard
    if session.get('user_id'):
        return redirect(url_for('dashboard'))

    server_ip = request.host.split(':')[0]
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <title>VantixBot</title>
  <style>
  {GLASS_CSS}
  </style>
</head>
<body>
  <div class="nav-bar">
    <div class="nav-inner">
      <div class="brand">
        <div class="brand-logo">
          <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
        </div>
        <div class="brand-name">VantixBot</div>
      </div>
      <div class="nav-links">
        <span>Features</span>
        <span>Pricing</span>
        <span>How It Works</span>
        <span>Testimonials</span>
        <span>FAQ</span>
        <span>Contact</span>
      </div>
    </div>
  </div>
  <div class="glass-root">
    <div class="glass-card">
      <div class="glass-card-inner">
        <div class="top-nav">
          <div class="badge success">API online · Proxy/VPN + weighted scoring</div>
          <a href="{{{{ url_for('login') }}}}">Login</a>
        </div>
        <h1><span>Bot Detection</span> Platform</h1>
        <p class="muted">Self-hosted bot & fraud detection with API keys and dashboard.</p>
        <p style="margin-top:18px;font-size:13px;">Quick health check:</p>
        <pre class="api-key-box" style="margin-top:8px;">curl http://{server_ip}/api/v1/health</pre>
        <p style="margin-top:16px;font-size:13px;">Or create a raw API key (without dashboard / trial):</p>
        <pre class="api-key-box" style="margin-top:8px;">curl -X POST http://{server_ip}/api/v1/create-key \\
  -H "Content-Type: application/json" \\
  -d '{{"email":"you@example.com","name":"Your Name"}}'</pre>
        <p class="muted" style="margin-top:18px;">For full experience (1-day trial, dashboard, admin control), please register and login.</p>
      </div>
    </div>
  </div>
</body>
</html>
    """
    return render_template_string(html)


# ---------------------------------------------------------------------------
# Auth & Dashboards (trial, regenerate API key, admin control)
# ---------------------------------------------------------------------------

def _current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)


@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        name = request.form.get('name', '').strip() or 'User'
        password = request.form.get('password', '')

        if not email or not password:
            error = "Email and password are required."
        elif User.query.filter_by(email=email).first():
            error = "Email already registered."
        else:
            error = None

        if error:
            return render_template_string(
                f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Register · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge warn">Trial registration</span>
            <a href="{{{{ url_for('login') }}}}">Login</a>
          </div>
          <h1><span>Register</span></h1>
          <p class="muted">Create your account and get a 1-day trial API key.</p>
          <p class="badge danger" style="margin-top:14px;">{{{{ error }}}}</p>
          <form method="post">
            <div class="field">
              <label>Email</label>
              <input type="email" name="email" value="{{{{ email }}}}" required>
            </div>
            <div class="field">
              <label>Name</label>
              <input type="text" name="name" value="{{{{ name }}}}" placeholder="Your name">
            </div>
            <div class="field">
              <label>Password</label>
              <input type="password" name="password" required>
            </div>
            <button class="btn" type="submit">Create account</button>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>
                """,
                error=error,
                email=email,
                name=name,
            )

        # Create user with 1-day trial
        trial_end = datetime.utcnow() + timedelta(days=1)
        user = User(
            email=email,
            name=name,
            password_hash=generate_password_hash(password),
            is_admin=False,
            trial_expires_at=trial_end,
        )
        db.session.add(user)
        db.session.flush()

        trial_key = APIKey(
            user_id=user.id,
            key=f"VTX-{secrets.token_hex(24)}",
            name="Trial Key",
            is_trial=True,
            expires_at=trial_end,
        )
        db.session.add(trial_key)
        db.session.commit()

        session['user_id'] = user.id
        return redirect(url_for('dashboard'))

    # GET
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Register · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge warn">1-day trial</span>
            <a href="{{{{ url_for('login') }}}}">Login</a>
          </div>
          <h1><span>Register</span></h1>
          <p class="muted">Create your account and get a 1-day trial API key.</p>
          <form method="post">
            <div class="field">
              <label>Email</label>
              <input type="email" name="email" required>
            </div>
            <div class="field">
              <label>Name</label>
              <input type="text" name="name" placeholder="Your name">
            </div>
            <div class="field">
              <label>Password</label>
              <input type="password" name="password" required>
            </div>
            <button class="btn" type="submit">Create account</button>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>
    """
    return render_template_string(html)


@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
            error = "Invalid email or password."
        else:
            error = None

        if error:
            return render_template_string(
                f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Login · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge">Welcome back</span>
            <a href="{{{{ url_for('register') }}}}">Register</a>
          </div>
          <h1><span>Login</span></h1>
          <p class="muted">Sign in to your dashboard.</p>
          <p class="badge danger" style="margin-top:14px;">{{{{ error }}}}</p>
          <form method="post">
            <div class="field">
              <label>Email</label>
              <input type="email" name="email" value="{{{{ email }}}}" required>
            </div>
            <div class="field">
              <label>Password</label>
              <input type="password" name="password" required>
            </div>
            <button class="btn" type="submit">Login</button>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>
                """,
                error=error,
                email=email,
            )

        session['user_id'] = user.id
        return redirect(url_for('dashboard'))

    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Login · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge">Welcome back</span>
            <a href="{{{{ url_for('register') }}}}">Register</a>
          </div>
          <h1><span>Login</span></h1>
          <p class="muted">Sign in to your dashboard.</p>
          <form method="post">
            <div class="field">
              <label>Email</label>
              <input type="email" name="email" required>
            </div>
            <div class="field">
              <label>Password</label>
              <input type="password" name="password" required>
            </div>
            <button class="btn" type="submit">Login</button>
          </form>
        </div>
      </div>
    </div>
  </body>
</html>
    """
    return render_template_string(html)


@app.route('/auth/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = _current_user()
    key = (
        APIKey.query.filter_by(user_id=user.id)
        .order_by(APIKey.created_at.desc())
        .first()
    )

    trial_expired = False
    days_left = None
    if key and key.expires_at:
        now = datetime.utcnow()
        if now > key.expires_at:
            trial_expired = True
            days_left = 0
        else:
            days_left = max(0, (key.expires_at - now).days)

    # Handle regenerate from POST
    message = ""
    if request.method == 'POST' and request.form.get('action') == 'regenerate':
        if not key:
            message = "No API key to regenerate."
        elif key.regenerate_count >= 7:
            message = "Regenerate limit reached (7x)."
        elif trial_expired:
            message = "Your trial has expired. Please contact admin."
        else:
            key.key = f"VTX-{secrets.token_hex(24)}"
            key.regenerate_count = (key.regenerate_count or 0) + 1
            db.session.commit()
            message = "API key regenerated successfully."

        # Recompute trial status after change
        key = (
            APIKey.query.filter_by(user_id=user.id)
            .order_by(APIKey.created_at.desc())
            .first()
        )
        if key and key.expires_at:
            now = datetime.utcnow()
            if now > key.expires_at:
                trial_expired = True
                days_left = 0
            else:
                days_left = max(0, (key.expires_at - now).days)

    server_ip = request.host.split(':')[0]
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Dashboard · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge">User dashboard</span>
            <a href="{{{{ url_for('logout') }}}}">Logout</a>
          </div>
          <h1><span>Hello, {{{{ user.name or 'User' }}}}</span></h1>
          <p class="muted">Use this API key in your application headers.</p>

          {% if trial_expired %}
            <p class="badge danger" style="margin-top:16px;">Your trial has been expired.</p>
          {% else %}
            <p class="badge success" style="margin-top:16px;">
              Trial active · {{ days_left }} day(s) remaining
            </p>
          {% endif %}

          {% if message %}
            <p class="badge" style="margin-top:12px;">{{ message }}</p>
          {% endif %}

          {% if key %}
            <div class="field" style="margin-top:18px;">
              <label>Your API key</label>
              <div class="api-key-box">{{ key.key }}</div>
              <p class="muted">Regenerate used {{ key.regenerate_count or 0 }}/7 times.</p>
            </div>
            <form method="post">
              <input type="hidden" name="action" value="regenerate">
              <button class="btn" type="submit" {% if trial_expired or (key.regenerate_count or 0) >= 7 %}disabled{% endif %}>
                Regenerate key
              </button>
            </form>
          {% else %}
            <p style="margin-top:18px;">You don't have an API key yet.</p>
          {% endif %}

          <p style="margin-top:22px;font-size:13px;">Detect endpoint:</p>
          <pre class="api-key-box">POST http://{server_ip}/api/v1/detect
Headers:
  X-API-Key: &lt;your-key&gt;
  Content-Type: application/json</pre>
        </div>
      </div>
    </div>
  </body>
</html>
    """
    return render_template_string(
        html,
        user=user,
        key=key,
        trial_expired=trial_expired,
        days_left=days_left,
        message=message,
    )


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    message = ""
    if request.method == 'POST':
        target_user_id = request.form.get('user_id')
        days = int(request.form.get('days', '0') or 0)
        if target_user_id and days > 0:
            target = User.query.get(int(target_user_id))
            if target:
                # Extend trial_expires_at at user level
                now = datetime.utcnow()
                if not target.trial_expires_at or target.trial_expires_at < now:
                    target.trial_expires_at = now + timedelta(days=days)
                else:
                    target.trial_expires_at = target.trial_expires_at + timedelta(days=days)

                # Extend all API keys for this user
                keys = APIKey.query.filter_by(user_id=target.id).all()
                for k in keys:
                    if not k.expires_at or k.expires_at < now:
                        k.expires_at = now + timedelta(days=days)
                    else:
                        k.expires_at = k.expires_at + timedelta(days=days)

                db.session.commit()
                message = f"Extended user {target.email} by {days} day(s)."

    users = User.query.order_by(User.created_at.desc()).all()
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Admin · VantixBot</title>
    <style>{GLASS_CSS}</style>
  </head>
  <body>
    <div class="nav-bar">
      <div class="nav-inner">
        <div class="brand">
          <div class="brand-logo">
            <img src="/static/vantixbot-logo.png" alt="VantixBot logo">
          </div>
          <div class="brand-name">VantixBot</div>
        </div>
        <div class="nav-links">
          <span>Features</span>
          <span>Pricing</span>
          <span>How It Works</span>
          <span>Testimonials</span>
          <span>FAQ</span>
          <span>Contact</span>
        </div>
      </div>
    </div>
    <div class="glass-root">
      <div class="glass-card">
        <div class="glass-card-inner">
          <div class="top-nav">
            <span class="badge">Admin panel</span>
            <a href="{{{{ url_for('dashboard') }}}}">Back to dashboard</a>
          </div>
          <h1><span>Users & API Keys</span></h1>
          <p class="muted">Only admin can extend trial / usage days.</p>

          {% if message %}
            <p class="badge success" style="margin-top:14px;">{{ message }}</p>
          {% endif %}

          <form method="post" style="margin-top:18px;">
            <div class="field">
              <label>Select user</label>
              <select name="user_id" required>
                <option value="">-- choose user --</option>
                {% for u in users %}
                  <option value="{{ u.id }}">{{ u.email }}{% if u.is_admin %} (admin){% endif %}</option>
                {% endfor %}
              </select>
            </div>
            <div class="field">
              <label>Extend days (e.g. 7 / 30)</label>
              <input type="number" name="days" min="1" value="7" required>
            </div>
            <button class="btn" type="submit">Extend usage</button>
          </form>

          <p style="margin-top:20px;font-size:13px;">Current users:</p>
          <ul style="margin-top:8px;font-size:13px;padding-left:18px;">
            {% for u in users %}
              <li>
                {{ u.email }}{% if u.is_admin %} · admin{% endif %}
                {% if u.trial_expires_at %}
                  · trial until {{ u.trial_expires_at.strftime('%Y-%m-%d') }}
                {% else %}
                  · no trial expiry
                {% endif %}
              </li>
            {% endfor %}
          </ul>
        </div>
      </div>
    </div>
  </body>
</html>
    """
    return render_template_string(html, users=users, message=message)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOFAPP
    
    # Create static directory and placeholder VantixBot logo
    mkdir -p "$PROJECT_DIR/backend/static"
    cat > "$PROJECT_DIR/backend/static/vantixbot-logo.png" << 'EOFLOGO'
<?xml version="1.0" encoding="UTF-8"?>
<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#38bdf8"/>
      <stop offset="50%" stop-color="#6366f1"/>
      <stop offset="100%" stop-color="#f97316"/>
    </linearGradient>
  </defs>
  <rect x="4" y="4" width="56" height="56" rx="16" fill="#020617"/>
  <rect x="4" y="4" width="56" height="56" rx="16" fill="url(#g)" opacity="0.22"/>
  <path d="M18 44L28 20H34L46 44H39.5L32 27.5L24.5 44H18Z" fill="#e5e7eb"/>
  <circle cx="48" cy="16" r="5" fill="#22c55e"/>
</svg>
EOFLOGO

    print_success "Backend files created"
}

################################################################################
# Step 7: SDK
################################################################################

create_sdk() {
    print_header "Step 7/12: Creating JavaScript SDK"
    
    cat > "$PROJECT_DIR/sdk/bot-detector.js" << 'EOFSDK'
(function(w){'use strict';class BotDetectorSDK{constructor(k,o={}){this.apiKey=k;this.endpoint=o.endpoint||w.location.origin+'/api/v1/detect';this.autoDetect=o.autoDetect!==false;this.onResult=o.onResult||null;this.data={};if(this.autoDetect)this.init()}async init(){await this.collectData();setTimeout(()=>this.detect(),2000)}async collectData(){this.data={screen_resolution:`${screen.width}x${screen.height}`,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,platform:navigator.platform,hardware_concurrency:navigator.hardwareConcurrency||0,canvas_hash:await this.getCanvasFingerprint(),webgl_vendor:this.getWebGLVendor(),mouse_events:0,key_events:0,time_on_page:0};this.trackBehavior()}async getCanvasFingerprint(){try{const c=document.createElement('canvas');const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillText('BotDetector',2,2);return c.toDataURL().substring(0,50)}catch(e){return'error'}}getWebGLVendor(){try{const c=document.createElement('canvas');const g=c.getContext('webgl');if(!g)return null;const d=g.getExtension('WEBGL_debug_renderer_info');return d?g.getParameter(d.UNMASKED_VENDOR_WEBGL):null}catch(e){return null}}trackBehavior(){const s=Date.now();document.addEventListener('mousemove',()=>this.data.mouse_events++,{passive:true});document.addEventListener('keydown',()=>this.data.key_events++,{passive:true});setInterval(()=>this.data.time_on_page=(Date.now()-s)/1000,1000)}async detect(){try{const r=await fetch(this.endpoint,{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':this.apiKey},body:JSON.stringify(this.data)});const d=await r.json();w.botDetectionResult=d;if(this.onResult)this.onResult(d);w.dispatchEvent(new CustomEvent('botDetectionComplete',{detail:d}));return d}catch(e){console.error('Bot detection error:',e);return{success:false,error:e.message}}}}if(typeof document!=='undefined'){const s=document.currentScript||document.querySelector('script[data-api-key]');if(s&&s.dataset.apiKey){w.botDetector=new BotDetectorSDK(s.dataset.apiKey,{endpoint:s.dataset.endpoint,onResult:(r)=>{if(r.bot_detected&&s.dataset.autoBlock==='true'){document.body.innerHTML=`<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:Arial;"><div style="text-align:center;"><h1>🚫 Access Denied</h1><p>Bot detected. Score: ${r.fraud_score}/100</p></div></div>`}}})}}w.BotDetectorSDK=BotDetectorSDK})(window);
EOFSDK
    
    print_success "SDK created"
}

################################################################################
# Step 8: Python Dependencies
################################################################################

install_python_deps() {
    print_header "Step 8/12: Installing Python Dependencies"
    
    cd "$PROJECT_DIR/backend"
    
    print_info "Creating virtual environment..."
    python3 -m venv venv
    
    print_info "Installing packages (may take 2-3 minutes)..."
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    
    print_success "Python dependencies installed"
}

################################################################################
# Step 9: Database
################################################################################

init_database() {
    print_header "Step 9/12: Initializing Database"
    
    cd "$PROJECT_DIR/backend"
    source venv/bin/activate
    
    print_info "Creating database tables & admin account..."
    
    # Prompt admin email & password
    read -rp "Enter ADMIN email (default: admin@vantixbot.local): " ADMIN_EMAIL
    ADMIN_EMAIL=${ADMIN_EMAIL:-admin@vantixbot.local}
    read -rsp "Enter ADMIN password (default: admin123): " ADMIN_PASSWORD_INPUT
    echo ""
    ADMIN_PASSWORD=${ADMIN_PASSWORD_INPUT:-admin123}
    
    python3 << 'EOFPY'
from app import app, db, User, APIKey
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import secrets, os

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@vantixbot.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

with app.app_context():
    db.create_all()

    # Create initial admin user (for accessing /admin)
    admin = User.query.filter_by(email=ADMIN_EMAIL).first()
    if not admin:
        trial_end = datetime.utcnow() + timedelta(days=30)
        admin = User(
            email=ADMIN_EMAIL,
            name="Admin",
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            is_admin=True,
            trial_expires_at=trial_end,
        )
        db.session.add(admin)
        db.session.flush()

        admin_key = APIKey(
            user_id=admin.id,
            key="VTX-ADMIN-" + secrets.token_hex(18),
            name="Admin Key",
            is_trial=False,
            expires_at=None,
        )
        db.session.add(admin_key)
        db.session.commit()
        print("=== VantixBot admin account created ===")
        print(f"Email    : {ADMIN_EMAIL}")
        print(f"Password : {ADMIN_PASSWORD}")
        print(f"API key  : {admin_key.key}")
    else:
        print("Admin user already exists.")
EOFPY
    
    print_success "Database initialized"
}

################################################################################
# Step 10: Threat Feeds
################################################################################

download_threat_feeds() {
    print_header "Step 10/12: Downloading Threat Feeds"
    
    DATA_DIR="$PROJECT_DIR/backend/data"
    
    print_info "Downloading free threat intelligence feeds..."
    
    # Feodo Tracker
    curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" 2>/dev/null | \
        grep -v "^#" | grep -v "^$" > "$DATA_DIR/feodo_blocklist.txt" || \
        touch "$DATA_DIR/feodo_blocklist.txt"
    
    # Emerging Threats
    curl -s "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" 2>/dev/null | \
        grep -v "^#" | grep -v "^$" > "$DATA_DIR/emerging_threats.txt" || \
        touch "$DATA_DIR/emerging_threats.txt"
    
    # TOR Exit Nodes
    curl -s "https://check.torproject.org/torbulkexitlist" 2>/dev/null | \
        grep -v "^#" | grep -v "^$" > "$DATA_DIR/tor_exit_nodes.txt" || \
        touch "$DATA_DIR/tor_exit_nodes.txt"
    
    print_success "Threat feeds downloaded"
}

################################################################################
# Step 11: Systemd Service
################################################################################

create_systemd_service() {
    print_header "Step 11/12: Creating System Service"
    
    sudo mkdir -p /var/log/botdetector
    sudo chown ubuntu:ubuntu /var/log/botdetector
    
    sudo tee /etc/systemd/system/botdetector.service > /dev/null << EOF
[Unit]
Description=Bot Detector API
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=$PROJECT_DIR/backend
Environment="PATH=$PROJECT_DIR/backend/venv/bin"
ExecStart=$PROJECT_DIR/backend/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 --timeout 30 --access-logfile /var/log/botdetector/access.log --error-logfile /var/log/botdetector/error.log app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable botdetector
    sudo systemctl start botdetector
    
    sleep 5
    
    if sudo systemctl is-active --quiet botdetector; then
        print_success "Service is running"
    else
        print_error "Service failed. Checking logs..."
        sudo journalctl -u botdetector -n 50 --no-pager
        exit 1
    fi
}

################################################################################
# Step 12: Nginx
################################################################################

configure_nginx() {
    print_header "Step 12/12: Configuring Nginx"
    
    LIGHTSAIL_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)
    
    sudo tee /etc/nginx/sites-available/botdetector > /dev/null << EOF
limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/s;

upstream backend {
    server 127.0.0.1:5000 fail_timeout=30s;
}

server {
    listen 80 default_server;
    server_name ${DOMAIN:-$LIGHTSAIL_IP} _;
    
    client_max_body_size 10M;
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        add_header Access-Control-Allow-Origin * always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, X-API-Key, Authorization" always;
        if (\$request_method = OPTIONS) {
            return 204;
        }
    }
    
    location /sdk/ {
        alias $PROJECT_DIR/sdk/;
        expires 1d;
        add_header Cache-Control "public, immutable";
        add_header Access-Control-Allow-Origin * always;
    }
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    
    sudo ln -sf /etc/nginx/sites-available/botdetector /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    
    sudo nginx -t
    if [ $? -eq 0 ]; then
        sudo systemctl reload nginx
        print_success "Nginx configured"
    else
        print_error "Nginx config error"
        exit 1
    fi
}

################################################################################
# Step 13: Cron
################################################################################

setup_cron() {
    print_info "Setting up automatic updates..."
    
    cat > "$PROJECT_DIR/scripts/update_feeds.sh" << 'EOFCRON'
#!/bin/bash
DATA_DIR="/home/ubuntu/bot-detection-platform/backend/data"
curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" 2>/dev/null | grep -v "^#" | grep -v "^$" > "$DATA_DIR/feodo_blocklist.txt"
curl -s "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" 2>/dev/null | grep -v "^#" | grep -v "^$" > "$DATA_DIR/emerging_threats.txt"
curl -s "https://check.torproject.org/torbulkexitlist" 2>/dev/null | grep -v "^#" | grep -v "^$" > "$DATA_DIR/tor_exit_nodes.txt"
EOFCRON
    
    chmod +x "$PROJECT_DIR/scripts/update_feeds.sh"
    
    (crontab -l 2>/dev/null | grep -v update_feeds; echo "0 */6 * * * $PROJECT_DIR/scripts/update_feeds.sh >> /var/log/botdetector/feeds.log 2>&1") | crontab -
    
    print_success "Cron configured"
}

################################################################################
# Example: Halaman contoh — pemakai SDK mengatur redirect URL di code mereka
################################################################################

create_example_redirect_page() {
    print_info "Creating example page (redirect URL diatur oleh pemakai di code mereka)..."
    
    LIGHTSAIL_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)
    API_BASE="http://${LIGHTSAIL_IP}"
    
    cat > "$PROJECT_DIR/example-redirect-if-bot.html" << 'EXEMPLO'
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading...</title>
</head>
<body>
    <p>Memeriksa...</p>
    <!-- 1. Ganti YOUR_KEY dengan API key Anda -->
    <!-- 2. Jika halaman ini tidak di-host di server API, data-endpoint wajib -->
    <script src="API_BASE_PLACEHOLDER/sdk/bot-detector.js"
            data-api-key="YOUR_KEY"
            data-endpoint="API_BASE_PLACEHOLDER/api/v1/detect"></script>
    <script>
        // Pemakai pendeteksian bot mengatur URL redirect di sini — sesuka mereka, tidak harus google.com
        var REDIRECT_IF_BOT = "https://www.google.com";

        function onResult(data) {
            if (data && data.bot_detected === true) window.location.replace(REDIRECT_IF_BOT);
        }
        window.addEventListener('botDetectionComplete', function(e) { if (e.detail) onResult(e.detail); });
        var t = setInterval(function() {
            if (window.botDetectionResult) { onResult(window.botDetectionResult); clearInterval(t); }
        }, 500);
        setTimeout(function() { clearInterval(t); }, 12000);
    </script>
</body>
</html>
EXEMPLO
    sed -i "s|API_BASE_PLACEHOLDER|$API_BASE|g" "$PROJECT_DIR/example-redirect-if-bot.html"
    
    print_success "Example: $PROJECT_DIR/example-redirect-if-bot.html"
}

################################################################################
# PHP integration: config.php + detector.php (pemakai cukup include detector.php)
################################################################################

create_php_integration() {
    print_info "Creating PHP integration (config.php + detector.php)..."
    
    LIGHTSAIL_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)
    mkdir -p "$PROJECT_DIR/php-integration"
    
    cat > "$PROJECT_DIR/php-integration/config.php" << CONFIGPHP
<?php
/**
 * Bot Detection API - Konfigurasi
 * Set API URL & key dari server Bot Detection Anda.
 */
\$apiUrl = 'http://$LIGHTSAIL_IP';
\$apiKey = 'YOUR_API_KEY';

\$isProtected = true;
\$unwantedVisitorTo = 'https://www.google.com';
\$unwantedVisitorAction = 1;
CONFIGPHP
    
    cat > "$PROJECT_DIR/php-integration/detector.php" << 'DETECTORPHP'
<?php
error_reporting(0);
ini_set('display_errors', 0);
include_once(__DIR__ . '/config.php');
if (!isset($isProtected) || $isProtected !== true) return;
if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
  $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
  $_SERVER['HTTP_CLIENT_IP'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
}
$clientIp = filter_var($_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP) ?: '';
if (strpos($clientIp, ',') !== false) $clientIp = trim(explode(',', $clientIp)[0]);
$apiUrl = rtrim($apiUrl ?? '', '/');
$apiKey = $apiKey ?? '';
if ($apiUrl === '' || $apiKey === '' || $apiKey === 'YOUR_API_KEY') return;
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$curl = curl_init();
curl_setopt_array($curl, [
  CURLOPT_URL => $apiUrl . '/api/v1/detect',
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_POST => true,
  CURLOPT_POSTFIELDS => json_encode(['mouse_events' => 0, 'time_on_page' => 0]),
  CURLOPT_TIMEOUT => 10,
  CURLOPT_HTTPHEADER => [
    'Content-Type: application/json',
    'X-API-Key: ' . $apiKey,
    'User-Agent: ' . $userAgent,
    'X-Forwarded-For: ' . $clientIp,
  ],
]);
$response = curl_exec($curl);
curl_close($curl);
$data = is_string($response) ? json_decode($response, true) : null;
$needToBlock = is_array($data) && !empty($data['bot_detected']);
if (!$needToBlock) return;
$unwantedVisitorTo = $unwantedVisitorTo ?? '';
$unwantedVisitorAction = (int)($unwantedVisitorAction ?? 1);
$options = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false], 'http' => ['header' => 'User-Agent: ' . ($_SERVER['HTTP_USER_AGENT'] ?? '')]];
if ($unwantedVisitorTo !== '') {
  if (is_numeric($unwantedVisitorTo)) { http_response_code((int)$unwantedVisitorTo); exit; }
  if ($unwantedVisitorAction === 2) {
    echo '<iframe src="' . htmlspecialchars($unwantedVisitorTo) . '" width="100%" height="100%"></iframe><style>body{margin:0;padding:0;}iframe{margin:0;padding:0;border:0;}</style>';
    exit;
  }
  if ($unwantedVisitorAction === 3) {
    if (filter_var($unwantedVisitorTo, FILTER_VALIDATE_URL)) {
      echo str_replace('<head>', '<head><base href="' . $unwantedVisitorTo . '" />', file_get_contents($unwantedVisitorTo, false, stream_context_create($options)));
      exit;
    }
    if (file_exists($unwantedVisitorTo)) {
      if (pathinfo($unwantedVisitorTo, PATHINFO_EXTENSION) === 'php') require_once $unwantedVisitorTo;
      else echo file_get_contents($unwantedVisitorTo, false, stream_context_create($options));
      exit;
    }
    exit('Unwanted Visitor Page Not Found.');
  }
  header('Expires: Mon, 23 Jul 1993 05:00:00 GMT');
  header('Cache-Control: no-store, no-cache, must-revalidate');
  header('Pragma: no-cache');
  header('Location: ' . $unwantedVisitorTo, true, 302);
  exit;
}
header('HTTP/1.0 403 Forbidden');
header('Cache-Control: no-store, no-cache, must-revalidate');
?>
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="robots" content="noindex,nofollow"></head>
<body style="background:#EEE;color:#000;font-family:sans-serif;text-align:center;padding:40px;">
  <h1>Access Denied</h1>
  <p>Your access has been blocked for security reasons.</p>
</body></html>
<?php exit;
DETECTORPHP
    
    echo "# Pemakai Bot Detection: include detector.php di setiap halaman yang ingin dilindungi." > "$PROJECT_DIR/php-integration/README.txt"
    echo "# Copy folder php-integration ke situs mereka, edit config.php (apiKey, unwantedVisitorTo, dll), lalu include_once(__DIR__ . '/detector.php');" >> "$PROJECT_DIR/php-integration/README.txt"
    
    # Build zip package for dashboard download
    (cd "$PROJECT_DIR" && zip -qr "vantix-detection.zip" "php-integration") || true
    
    print_success "PHP integration: $PROJECT_DIR/php-integration/ + vantix-detection.zip"
}

################################################################################
# Final Summary
################################################################################

final_summary() {
    print_header "🎉 INSTALLATION COMPLETE!"
    
    LIGHTSAIL_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me)
    
    # Get demo key
    DEMO_KEY=$(cd "$PROJECT_DIR/backend" && source venv/bin/activate && python3 -c "from app import app, db, APIKey; app.app_context().push(); key = APIKey.query.first(); print(key.key if key else '')" 2>/dev/null)
    
    cat << EOF

╔════════════════════════════════════════════════════════════════╗
║         BOT DETECTION PLATFORM - AWS LIGHTSAIL                 ║
║              Installation Successful! ✅                        ║
╚════════════════════════════════════════════════════════════════╝

☁️  Your Lightsail Instance:
   Public IP: $LIGHTSAIL_IP
   $([ -n "$DOMAIN" ] && echo "Domain: $DOMAIN")

🔗 Access URLs:
   Dashboard: http://$LIGHTSAIL_IP
   API: http://$LIGHTSAIL_IP/api/v1
   Health: http://$LIGHTSAIL_IP/api/v1/health
   SDK: http://$LIGHTSAIL_IP/sdk/bot-detector.js

🔑 Demo API Key:
   $DEMO_KEY

📝 Quick Test:

   # 1. Health Check
   curl http://$LIGHTSAIL_IP/api/v1/health

   # 2. Create Your API Key
   curl -X POST http://$LIGHTSAIL_IP/api/v1/create-key \\
     -H "Content-Type: application/json" \\
     -d '{"email":"$EMAIL","name":"My Key"}'

   # 3. Test Detection
   curl -X POST http://$LIGHTSAIL_IP/api/v1/detect \\
     -H "X-API-Key: $DEMO_KEY" \\
     -H "Content-Type: application/json" \\
     -d '{"mouse_events":10,"time_on_page":5}'

   # 4. View Stats
   curl http://$LIGHTSAIL_IP/api/v1/stats \\
     -H "X-API-Key: $DEMO_KEY"

🌐 Cara dipakai oleh pemakai pendeteksian bot:
   Mereka tempel SDK di halaman mereka dan atur redirect URL di code mereka (bebas, tidak harus google.com).
   Contoh: $PROJECT_DIR/example-redirect-if-bot.html

   Di code mereka:
   <script src="http://$LIGHTSAIL_IP/sdk/bot-detector.js"
           data-api-key="YOUR_KEY"
           data-endpoint="http://$LIGHTSAIL_IP/api/v1/detect"></script>
   <script>
     var REDIRECT_IF_BOT = "https://url-yang-mereka-inginkan.com";  // pemakai yang atur
     window.addEventListener('botDetectionComplete', function(e) {
       if (e.detail && e.detail.bot_detected) window.location.replace(REDIRECT_IF_BOT);
     });
   </script>

📊 Management:

   sudo journalctl -u botdetector -f        # View logs
   sudo systemctl restart botdetector        # Restart
   sudo systemctl status botdetector         # Status

📂 Directories:
   Project: $PROJECT_DIR
   Logs: /var/log/botdetector

🔄 Auto-Updates: Every 6 hours

⚠️  IMPORTANT - Lightsail Firewall:
   1. Go to Lightsail Console
   2. Click your instance → Networking tab
   3. Make sure these ports are open:
      ✅ HTTP (80) - All IP addresses
      ✅ HTTPS (443) - All IP addresses

📁 Penerapan PHP (seperti moonito):
   Folder: $PROJECT_DIR/php-integration/
   Beri pemakai: config.php + detector.php. Mereka cukup:
   1. Edit config.php (apiKey, unwantedVisitorTo = URL yang mereka mau, unwantedVisitorAction = 1/2/3)
   2. Di file PHP mereka: include_once(__DIR__ . '/detector.php');

💡 Next Steps:
   1. Open http://$LIGHTSAIL_IP in browser
   2. Create your API key
   3. Beri pemakai: folder php-integration atau SDK + contoh redirect

Happy bot hunting! 🤖🔍

══════════════════════════════════════════════════════════════════
EOF
}

################################################################################
# Main
################################################################################

main() {
    welcome
    install_dependencies
    setup_firewall
    setup_directories
    setup_postgresql
    setup_redis
    create_backend_files
    create_sdk
    install_python_deps
    init_database
    download_threat_feeds
    create_systemd_service
    configure_nginx
    setup_cron
    create_example_redirect_page
    create_php_integration
    final_summary
}

main
