# Eve - Xui Manager | Quick Installation Guide

سریع ترین راه برای نصب Eve - Xui Manager روی VPS شما

---

## Prerequisites (پیش‌نیازها)

- **Ubuntu/Debian Server** (20.04 یا جدیدتر توصیه شده)
- **Root یا sudo access**
- **Internet connection**
- Minimum **2GB RAM**, **10GB Storage**

---

## Step 1: Update System و Install Dependencies

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3.11 python3.11-venv python3-pip postgresql postgresql-contrib curl git nano
```

---

## Step 2: Setup PostgreSQL Database

```bash
# شروع PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# وارد شدن به PostgreSQL
sudo -u postgres psql

# داخل PostgreSQL، دستورات زیر را اجرا کنید:
CREATE USER eve_user WITH PASSWORD 'your_secure_password_here';
CREATE DATABASE eve_db OWNER eve_user;
ALTER ROLE eve_user SET client_encoding TO 'utf8';
ALTER ROLE eve_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE eve_user SET default_transaction_deferrable TO on;
ALTER ROLE eve_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE eve_db TO eve_user;
\q
```

⚠️ **تغییر دهید**: `your_secure_password_here` را با رمز قوی جایگزین کنید

---

## Step 3: Clone Repository و Setup Application

```bash
# Clone کردن پروژه
cd /opt
sudo git clone https://github.com/yoyoraya/eve-xui-manager.git
sudo cd eve-xui-manager
sudo chown -R $USER:$USER .

# ایجاد Python virtual environment
python3.11 -m venv venv
source venv/bin/activate

# نصب dependencies
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-limiter psycopg2-binary qrcode pillow requests werkzeug jdatetime urllib3
```

---

## Step 4: Environment Configuration

```bash
# Create .env file
nano .env
```

**Copy این content و پیست کنید:**

```env
# Database
DATABASE_URL=postgresql://eve_user:your_secure_password_here@localhost:5432/eve_db

# Security
SESSION_SECRET=your_very_long_random_secret_key_here_12345678901234567890
INITIAL_ADMIN_PASSWORD=change_this_admin_password

# Optional: Default X-UI Server (اختیاری)
# XUI_HOST=https://your-xui-panel.com
# XUI_USERNAME=admin
# XUI_PASSWORD=admin_password
```

**تغییرات لازم:**
- `your_secure_password_here` → رمز PostgreSQL (از Step 2)
- `your_very_long_random_secret_key_here_12345678901234567890` → عبارت تصادفی طولانی
- `change_this_admin_password` → رمز admin که بعدا می‌تونید تغییر بدید

**Ctrl+X ثم Y ثم Enter برای ذخیره**

---

## Step 5: Initialize Database

```bash
# Activate virtual environment
source venv/bin/activate

# ایجاد جداول database
python3 << EOF
from app import app, db
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")
EOF
```

---

## Step 6: Test Application (اختیاری)

```bash
# تست اجرای برنامه
python app.py
```

خواهید دید:
```
Running on http://0.0.0.0:5000
```

**Ctrl+C برای خروج**

---

## Step 7: Setup Systemd Service (برای اجرای دائمی)

```bash
# Create service file
sudo nano /etc/systemd/system/eve-xui-manager.service
```

**Copy این content:**

```ini
[Unit]
Description=Eve - Xui Manager VPN Panel
After=network.target postgresql.service
StartLimitIntervalSec=0

[Service]
Type=notify
User=root
WorkingDirectory=/opt/eve-xui-manager
Environment="PATH=/opt/eve-xui-manager/venv/bin"
EnvironmentFile=/opt/eve-xui-manager/.env
ExecStart=/opt/eve-xui-manager/venv/bin/gunicorn --workers 2 --threads 4 --worker-class gthread --bind 0.0.0.0:5000 --timeout 120 --graceful-timeout 30 --keep-alive 5 --max-requests 1000 --max-requests-jitter 100 app:app

# Restart on failure
Restart=always
RestartSec=3
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Ctrl+X ثم Y ثم Enter برای ذخیره**

---

## Step 8: Enable و Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (برای شروع خودکار)
sudo systemctl enable eve-xui-manager

# Start service
sudo systemctl start eve-xui-manager

# Check status
sudo systemctl status eve-xui-manager

# Health check (should return success:true)
curl -s http://127.0.0.1:5000/healthz
```

✅ اگر `active (running)` دیدید، همه چیز OK است!

---

## Step 9: Setup Reverse Proxy (Nginx)

```bash
# Install Nginx
sudo apt install -y nginx

# Create Nginx config
sudo nano /etc/nginx/sites-available/eve-xui-manager
```

**Copy این content:**

```nginx
upstream eve_app {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name your-domain.com;  # تغییر دهید

    client_max_body_size 10M;

    location / {
        proxy_pass http://eve_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /opt/eve-xui-manager/static/;
    }
}
```

**Ctrl+X ثم Y ثم Enter برای ذخیره**

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/eve-xui-manager /etc/nginx/sites-enabled/

# Test Nginx config
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

---

## Step 10: Setup SSL/HTTPS (اختیاری اما توصیه شده)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com  # تغییر دهید

# Verify auto-renewal
sudo systemctl enable certbot.timer
```

---

## 🎉 Installation Complete!

### Access the Panel

- **URL**: `http://your-server-ip:5000` یا `https://your-domain.com`
- **Default Username**: `admin`
- **Default Password**: از `.env` فایل (متغیر `INITIAL_ADMIN_PASSWORD`)

### ⚠️ Security First!

**بلافاصله بعد از ورود:**
1. رمز admin را تغییر دهید
2. `SESSION_SECRET` را در `.env` تغییر دهید
3. `INITIAL_ADMIN_PASSWORD` را تغییر دهید

```bash
# برای اعمال تغییرات
sudo systemctl restart eve-xui-manager
```

---

## 📝 Useful Commands

```bash
# Check service status
sudo systemctl status eve-xui-manager

# View logs
sudo journalctl -u eve-xui-manager -f

# Restart service
sudo systemctl restart eve-xui-manager

# Stop service
sudo systemctl stop eve-xui-manager

# Start service
sudo systemctl start eve-xui-manager

# Reload environment variables
sudo systemctl daemon-reload

# Update from GitHub
cd /opt/eve-xui-manager
git pull origin main
source venv/bin/activate
pip install -r requirements.txt  # if exists
sudo systemctl restart eve-xui-manager
```

---

## 🔧 Troubleshooting

### برنامه شروع نمی‌شود

```bash
# Check logs
sudo journalctl -u eve-xui-manager -n 50

# Test database connection
python3 << EOF
from urllib.parse import urlparse
print(urlparse("YOUR_DATABASE_URL"))
EOF
```

### خطای Connection refused

- بررسی کنید که PostgreSQL در حال اجرا است: `sudo systemctl status postgresql`
- بررسی کنید که رمز صحیح است در `.env`

### Nginx 502 Bad Gateway

```bash
# بررسی اینکه app در حال اجرا است
sudo systemctl status eve-xui-manager

# Restart both
sudo systemctl restart eve-xui-manager
sudo systemctl restart nginx
```

---

## 📞 Support

اگر مشکل دارید:
- Check GitHub issues: https://github.com/yoyoraya/eve-xui-manager/issues
- Review logs: `sudo journalctl -u eve-xui-manager -f`
- Test app locally: `source venv/bin/activate && python app.py`

---

## 📚 Additional Resources

- **Flask Documentation**: https://flask.palletsprojects.com/
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **Nginx Documentation**: https://nginx.org/en/docs/

---

**Happy deploying! 🚀**
