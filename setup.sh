#!/bin/bash

# Eve - Xui Manager Quick Installer
# Author: Yoyoraya
# License: MIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}       Eve - Xui Manager | Quick Installer        ${NC}"
echo -e "${BLUE}==================================================${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ Please run as root (sudo -i)${NC}"
  exit 1
fi

# 2. Get Domain or IP
echo -e "${YELLOW}👉 Enter your Domain or IP Address (e.g., panel.example.com or 1.2.3.4):${NC}"
read -p "Domain/IP: " USER_DOMAIN
if [ -z "$USER_DOMAIN" ]; then
    echo -e "${RED}❌ Domain/IP is required!${NC}"
    exit 1
fi

# 3. System Update & Dependencies
echo -e "${GREEN}📦 Updating system and installing dependencies...${NC}"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip python3-dev git postgresql postgresql-contrib nginx curl libpq-dev build-essential

# 4. Setup Database Credentials (Random Generation)
DB_NAME="eve_db"
DB_USER="eve_user"
DB_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
APP_SECRET=$(openssl rand -hex 32)
ADMIN_PASS="admin123" # Default, user should change it

echo -e "${GREEN}🗄️  Configuring PostgreSQL...${NC}"
# Create DB user and database if not exists
sudo -u postgres psql -c "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1 || sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
sudo -u postgres psql -c "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 || sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# 5. Clone & Setup Project
INSTALL_DIR="/opt/eve-xui-manager"
REPO_URL="https://github.com/yoyoraya/eve-xui-manager.git"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}⚠️  Directory $INSTALL_DIR exists. Updating...${NC}"
    cd $INSTALL_DIR
    git pull
else
    echo -e "${GREEN}⬇️  Cloning repository...${NC}"
    git clone $REPO_URL $INSTALL_DIR
    cd $INSTALL_DIR
fi

# Permissions
chown -R root:root $INSTALL_DIR
chmod -R 755 $INSTALL_DIR

# 6. Setup Python Environment
echo -e "${GREEN}🐍 Setting up Python environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn psycopg2-binary

# 7. Create .env File
echo -e "${GREEN}🔒 Creating secure configuration...${NC}"
cat > .env <<EOF
DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost/${DB_NAME}
SESSION_SECRET=${APP_SECRET}
INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}
EOF

# 8. Initialize Database Tables
echo -e "${GREEN}🛠️  Initializing database tables...${NC}"
python3 << EOF
from app import app, db
try:
    with app.app_context():
        db.create_all()
        print("Database tables created successfully.")
except Exception as e:
    print(f"Error: {e}")
EOF

# 9. Setup Systemd Service
echo -e "${GREEN}⚙️  Creating system service...${NC}"
cat > /etc/systemd/system/eve-manager.service <<EOF
[Unit]
Description=Eve Xui Manager Service
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable eve-manager
systemctl restart eve-manager

# 10. Setup Nginx Reverse Proxy
echo -e "${GREEN}🌐 Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/eve-manager <<EOF
server {
    listen 80;
    server_name ${USER_DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static/ {
        alias ${INSTALL_DIR}/static/;
    }
}
EOF

ln -sf /etc/nginx/sites-available/eve-manager /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

# 11. Final Output
echo -e "${BLUE}==================================================${NC}"
echo -e "${GREEN}✅ Installation Completed Successfully!${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "🔗 URL:      http://${USER_DOMAIN}"
echo -e "👤 Username: admin"
echo -e "🔑 Password: ${ADMIN_PASS}"
echo -e "${YELLOW}⚠️  IMPORTANT: Change the default password immediately after login!${NC}"
echo -e "${BLUE}==================================================${NC}"