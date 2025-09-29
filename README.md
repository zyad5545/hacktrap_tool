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
