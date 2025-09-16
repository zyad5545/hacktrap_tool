#!/bin/bash
echo "Starting HackTrap demo environment..."
docker compose up --build -d
echo "Waiting for services to start..."
sleep 15
echo "Running demo attack simulation..."
python3 scripts/demo_attack.py --target http://localhost:8000
echo "Demo environment ready!"
echo "Dashboard: http://localhost:8080"
echo "API: http://localhost:8000"