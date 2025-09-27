# HackTrap Project

A comprehensive security monitoring and attack detection system with blockchain-based evidence anchoring.

## Features

- Real-time attack detection
- AI-powered anomaly detection
- Blockchain evidence anchoring
- Interactive dashboard
- Automated response system

## Quick Start

1. Clone the repository
2. Optional: create `.env` in project root with:
   - `BLOCKCHAIN_RPC=http://blockchain:8545`
   - `CHAIN_ID=1337`
   - `CONTRACT_ADDRESS=0xYourDeployedContract` (optional; anchoring skips if missing)
   - `RELAYER_PRIVATE_KEY=0x...` (optional; anchoring skips if missing)
   - `ANCHORING_ENABLED=true`
3. Train AI model (one-time):
   - `docker compose run --rm ai_engine python /app/train_model.py`
   - This writes `data/model.pkl` mounted into the AI engine
4. Start stack: `docker compose up --build`
5. Open dashboard: http://localhost:8080
6. Demo endpoints:
   - `POST http://localhost:8080/login` JSON `{ "username":"x","password":"y" }`
   - `GET  http://localhost:8080/search?q=<script>alert(1)</script>`
   - `GET  http://localhost:8080/id?id=1 OR 1=1 --`
   - Attacks appear on `Attacks` page; honeypot sessions at `/api/honeypot/sessions`

## Services

- Backend Flask at `backend:8000`
- AI Engine at `ai_engine:5000`
- Cowrie honeypot at ports 2222/2223, logs in `cowrie-data/var/log`
- Ganache test chain at `blockchain:8545`
- Nginx dashboard at port 8080

## Documentation

See `docs/DEMO.md` for demonstration instructions and attack simulation examples.