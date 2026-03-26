#!/bin/bash

# Multi-Agent Framework EC2 Setup Script

# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Docker if not already present
if ! [ -x "$(command -v docker)" ]; then
  echo "Installing Docker..."
  sudo apt install -y docker.io
  sudo usermod -aG docker $USER
fi

# 3. Install Docker Compose if not already present
if ! [ -x "$(command -v docker-compose)" ]; then
  echo "Installing Docker Compose..."
  sudo apt install -y docker-compose
fi

# 4. Set environment variables
if [ ! -f .env ]; then
  echo "Creating default .env file..."
  cat <<EOF > .env
DATABASE_URL=postgresql://user:password@postgres:5432/agent_registry
ETCD_ENDPOINT=http://etcd:2379
PUBLIC_API_URL=http://localhost:8000
EOF
fi

# 5. Start the framework
echo "Starting Multi-Agent Framework..."
docker-compose up -d

# 6. Initialize database
echo "Waiting for PostgreSQL to start..."
sleep 10
docker-compose exec control-plane alembic upgrade head

# 7. Seed initial data
echo "Seeding initial data..."
docker-compose exec control-plane python scripts/seed_db.py

echo "Deployment complete! Access the Web UI at http://localhost"
