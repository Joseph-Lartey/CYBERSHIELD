# 🛡️ CyberShield - AI-Powered Intrusion Detection for SMEs

# Overiew 
CyberShield is an AI-powered browser-based Intrusion Detection System (IDS) designed to help Small and Medium-sized Enterprises (SMEs) in Ghana detect ransomware threats in real time. Built as a Chrome extension with a secure cloud-hosted backend, it leverages machine learning to identify suspicious web activity and automatically trigger lightweight incident responses.

# Features 

- 🔍 Real-time threat detection via browser extension
- 📡 Lightweight traffic capture using Chrome APIs
- 🧠 Machine learning-based threat classification (Random Forest)
- 🚨 Alerting system with notifications and tab auto-close
- 🗂️ Log export functionality
- 🌐 HTTPS-secured communication (Nginx + Certbot)
- ☁️ Hosted on AWS EC2 with Gunicorn + systemd

# System Architecture
![System Architecture](assets/architecture.png)
*Fig 1: Updated Microservices Architecture of CyberShield*

# Tech Stack 
- **Frontend:** Chrome Extension (HTML, CSS, JS)
- **Backend:** Flask, Gunicorn, Python
- **Machine Learning:** Scikit-Learn, Pandas, Joblib
- **Deployment:** Amazon EC2, Nginx, systemd
- **Security:** SSL/TLS (Let's Encrypt), IP filtering
- **Containerization (optional):** Docker

# Installation Instructions
### Local Setup (Backend)
```bash
git clone https://github.com/your-username/cybershield.git
cd cybershield/backend
pip install -r requirements.txt
python alert_service.py
python detection_api.py
```

### Chrome Extension
1. Navigate to `chrome://extensions/`
2. Enable Developer Mode
3. Click "Load Unpacked" and select the `extension` folder

# Usage
- Toggle protection from the popup
- Click "Disable Alerts" to suppress UI notifications (incident response still runs)
- Use "Export Logs" to download local threat logs

# CI/CD Setup
GitHub Actions workflow (`.github/workflows/deploy.yml`) ensures automated deployment to EC2 using SSH. Every push to `main` triggers:
- Code sync via SCP
- Automatic restart of backend services via `systemctl`

# Security

- 🔐 End-to-end encryption (HTTPS via Nginx + Certbot)
- 🔐 Alerts and logs only visible to local extension instance
- 🔒 Backend access restricted to EC2 only via private key

# Screenshot
![Notifications UI](assets/notify.png)
![Mian UI](assets/UI.png)

## 👥 Contributors

- [@Joseph-Lartey](https://github.com/Joseph-Lartey)
- [@rama-boat](https://github.com/rama-boat)


