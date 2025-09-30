# HackTrap Project

A comprehensive security monitoring and attack detection system with blockchain-based evidence anchoring.

## Features

- Real-time attack detection
- AI-powered anomaly detection
- Blockchain evidence anchoring
- Interactive dashboard
- Automated response system

## Quick Start

1. git clone https://github.com/zyad5545/hacktrap_tool.git
2. cd hacktrap_tool
3. cat > .env <<'ENV'
# example .env — edit before running
ADMIN_API_KEY=honeypot-secure-key
CHAIN_ID=137
EXPLORER_BASE_137=https://polygonscan.com/tx/
HONEYPOT_DB=./data/honeypot.db
ENV
4.curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null 
5.docker compose build
docker compose up -d
2. Copy `.env.example` to `.env` and configure your settings
3. Run `docker compose up --build`
4. Access the dashboard at http://localhost:8080/
                                                original_search.html     #for simulate xss attack.
                                                original_login.html     #for simulate bruteforce attack.
                                                fake_search.html        #is a honeypot (the fake system)
                                                dashboard.html          #show alerts and see the place of the attacks.
                                                attacks.html            #show all attacks and see a flow chart for the type of the attack and how risk of it.
                                                blockchain.html         #show the blockchain of the logs 
                                                settings.html           #for clear all logs
                                                login.html              #for login on dashboard.html and the username:demo & password:demo123



## Documentation

See `docs/DEMO.md` for demonstration instructions and attack simulation examples.
