#!/bin/bash

################################################################################
#
# BOT DETECTION PLATFORM - AWS LIGHTSAIL INSTALLER
# Optimized untuk AWS Lightsail Ubuntu 22.04
# Version: 1.0
#
# CARA PAKAI:
# 1. ssh ke lightsail instance
# 2. nano install.sh
# 3. copy paste SEMUA script ini
# 4. chmod +x install.sh
# 5. bash install.sh
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
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib, secrets, redis, json, os
from dotenv import load_dotenv
import user_agents

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=int(os.getenv('REDIS_PORT', 6379)), decode_responses=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), default='API Key')
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    requests_per_hour = db.Column(db.Integer, default=1000)
    requests_per_day = db.Column(db.Integer, default=10000)

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

class DetectionEngine:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.data_dir = os.path.join(os.path.dirname(__file__), 'data')
    
    def analyze(self, ip, user_agent, headers, client_data):
        score, reasons = 0, []
        ip_score, ip_reasons = self._check_ip(ip)
        score += ip_score
        reasons.extend(ip_reasons)
        ua_score, ua_reasons = self._check_ua(user_agent)
        score += ua_score
        reasons.extend(ua_reasons)
        behavior_score, behavior_reasons = self._check_behavior(client_data)
        score += behavior_score
        reasons.extend(behavior_reasons)
        fingerprint = self._fingerprint(client_data)
        fp_score, fp_reasons = self._check_fingerprint(fingerprint)
        score += fp_score
        reasons.extend(fp_reasons)
        velocity_score, velocity_reasons = self._check_velocity(ip)
        score += velocity_score
        reasons.extend(velocity_reasons)
        is_bot = score >= 50
        risk = "high" if score >= 70 else "medium" if score >= 40 else "low"
        return {"bot_detected": is_bot, "fraud_score": min(score, 100), "risk_level": risk, "reasons": list(set(reasons)), "ip_address": ip, "fingerprint": fingerprint, "timestamp": datetime.now().isoformat()}
    
    def _check_ip(self, ip):
        score, reasons = 0, []
        cache_key = f"ip:{ip}"
        cached = self.redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return data['score'], data['reasons']
        for fname in ['feodo_blocklist.txt', 'emerging_threats.txt', 'tor_exit_nodes.txt']:
            fpath = os.path.join(self.data_dir, fname)
            if os.path.exists(fpath):
                with open(fpath) as f:
                    if ip in f.read():
                        score += 60
                        reasons.append("malicious_ip")
                        break
        if any(ip.startswith(p) for p in ['3.', '13.', '18.', '52.', '54.', '35.', '44.']):
            score += 10
            reasons.append("cloud_ip")
        self.redis.setex(cache_key, 3600, json.dumps({'score': score, 'reasons': reasons}))
        return score, reasons
    
    def _check_ua(self, ua_string):
        if not ua_string or len(ua_string) < 10:
            return 40, ["missing_user_agent"]
        score, reasons = 0, []
        ua = user_agents.parse(ua_string)
        if ua.is_bot:
            score += 50
            reasons.append("bot_user_agent")
        keywords = ['selenium', 'puppeteer', 'headless', 'bot', 'crawler', 'scraper', 'phantom']
        if any(k in ua_string.lower() for k in keywords):
            score += 45
            reasons.append("automation_detected")
        return score, reasons
    
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
            reasons.append("no_canvas_fingerprint")
        return score, reasons
    
    def _fingerprint(self, data):
        fp = f"{data.get('screen_resolution','')}{data.get('timezone','')}{data.get('canvas_hash','')}"
        return hashlib.sha256(fp.encode()).hexdigest()[:16]
    
    def _check_fingerprint(self, fp):
        key = f"fp:{fp}"
        count = self.redis.incr(key)
        self.redis.expire(key, 3600)
        if count > 50:
            return 40, ["fingerprint_reuse"]
        return 0, []
    
    def _check_velocity(self, ip):
        key = f"vel:{ip}"
        count = self.redis.incr(key)
        self.redis.expire(key, 60)
        if count > 30:
            return 35, ["high_velocity"]
        return 0, []

detector = DetectionEngine(redis_client)

def verify_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return None, {"error": "API key required"}, 401
    key_obj = APIKey.query.filter_by(key=api_key, active=True).first()
    if not key_obj:
        return None, {"error": "Invalid API key"}, 401
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
    log = DetectionLog(api_key_id=key_obj.id, ip_address=ip, user_agent=ua, is_bot=result['bot_detected'], fraud_score=result['fraud_score'], risk_level=result['risk_level'], reasons=result['reasons'])
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
    today = DetectionLog.query.filter(DetectionLog.api_key_id == key_obj.id, DetectionLog.timestamp >= datetime.now().date()).count()
    recent = DetectionLog.query.filter_by(api_key_id=key_obj.id).order_by(DetectionLog.timestamp.desc()).limit(20).all()
    return jsonify({"total_requests": total, "bots_detected": bots, "bot_percentage": round((bots/total*100) if total > 0 else 0, 2), "today_requests": today, "recent": [{"ip": r.ip_address, "is_bot": r.is_bot, "score": r.fraud_score, "risk": r.risk_level, "reasons": r.reasons, "time": r.timestamp.isoformat()} for r in recent]})

@app.route('/api/v1/create-key', methods=['POST'])
def create_key():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        user = User(email=data['email'], name=data.get('name', 'User'))
        db.session.add(user)
        db.session.flush()
    key = APIKey(user_id=user.id, key=f"sk_live_{secrets.token_hex(24)}", name=data.get('key_name', 'API Key'))
    db.session.add(key)
    db.session.commit()
    return jsonify({"success": True, "api_key": key.key})

@app.route('/api/v1/health')
def health():
    try:
        db.session.execute('SELECT 1')
        redis_client.ping()
        return jsonify({"status": "healthy", "db": "ok", "redis": "ok", "platform": "AWS Lightsail"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/')
def index():
    server = request.host
    return render_template_string('''<!DOCTYPE html>
<html><head><title>Bot Detection API</title><style>
body{font-family:Arial;max-width:900px;margin:50px auto;padding:20px;background:#f5f5f5}
.container{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h1{color:#2563eb;border-bottom:3px solid #2563eb;padding-bottom:10px}
.status{background:#d1fae5;color:#065f46;padding:15px;border-radius:5px;margin:20px 0}
.platform{background:#dbeafe;color:#1e40af;padding:10px;border-radius:5px;margin:10px 0}
pre{background:#1f2937;color:#f9fafb;padding:15px;border-radius:5px;overflow-x:auto;font-size:13px}
code{background:#1f2937;color:#f9fafb;padding:2px 6px;border-radius:3px}
</style></head><body><div class="container">
<h1>🤖 Bot Detection API</h1>
<div class="status">✅ API Running Successfully!</div>
<div class="platform">☁️ Powered by AWS Lightsail</div>
<h2>Quick Start</h2>
<h3>1. Create API Key</h3>
<pre>curl -X POST http://''' + server + '''/api/v1/create-key \\
  -H "Content-Type: application/json" \\
  -d '{"email":"you@example.com","name":"Your Name"}'</pre>
<h3>2. Test Detection</h3>
<pre>curl -X POST http://''' + server + '''/api/v1/detect \\
  -H "X-API-Key: YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"mouse_events":10,"time_on_page":5}'</pre>
<h3>3. Integration</h3>
<pre>&lt;script src="http://''' + server + '''/sdk/bot-detector.js"
    data-api-key="YOUR_KEY"&gt;&lt;/script&gt;</pre>
</div></body></html>''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOFAPP
    
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
    
    print_info "Creating database tables..."
    
    python3 << 'EOFPY'
from app import app, db, User, APIKey
import secrets

with app.app_context():
    db.create_all()
    demo_user = User.query.filter_by(email='demo@lightsail.local').first()
    if not demo_user:
        demo_user = User(email='demo@lightsail.local', name='Demo User')
        db.session.add(demo_user)
        db.session.flush()
        demo_key = APIKey(user_id=demo_user.id, key='sk_test_lightsail_' + secrets.token_hex(18), name='Demo API Key')
        db.session.add(demo_key)
        db.session.commit()
        print(demo_key.key)
    else:
        key = APIKey.query.filter_by(user_id=demo_user.id).first()
        print(key.key if key else 'No key found')
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

🌐 Website Integration:

   <script 
       src="http://$LIGHTSAIL_IP/sdk/bot-detector.js"
       data-api-key="YOUR_KEY"
       data-auto-block="true">
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

💡 Next Steps:
   1. Open http://$LIGHTSAIL_IP in browser
   2. Create your API key
   3. Test detection
   4. Integrate into website!

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
    final_summary
}

main
