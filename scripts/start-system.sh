#!/bin/bash
echo "Starting HackTrap System..."
echo "Building and starting containers..."

# Build with increased timeout and no cache if needed
docker-compose build --timeout 600
docker-compose up -d

echo "Waiting for services to initialize..."
sleep 15

echo "System status:"
docker-compose ps

echo "HackTrap system is now running!"
echo "Dashboard: http://localhost:8080"
echo "Backend API: http://localhost:8000"
echo "Blockchain RPC: http://localhost:8545"