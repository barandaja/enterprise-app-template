#!/bin/bash

# Clean Start Script for Enterprise App Template
# This script ensures a clean deployment from scratch

set -e

echo "🚀 Starting clean deployment..."

# 1. Start database services first
echo "📦 Starting PostgreSQL and Redis..."
docker compose up -d postgres redis

# 2. Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# 3. Create databases
echo "🗄️ Creating databases..."
docker exec enterprise_postgres psql -U enterprise_user -d enterprise_db -c "CREATE DATABASE auth_db;" || echo "auth_db already exists"
docker exec enterprise_postgres psql -U enterprise_user -d enterprise_db -c "CREATE DATABASE user_db;" || echo "user_db already exists"
docker exec enterprise_postgres psql -U enterprise_user -d enterprise_db -c "CREATE DATABASE gateway_db;" || echo "gateway_db already exists"

# 4. Start auth service and run migrations
echo "🔐 Starting auth service and running migrations..."
docker compose up -d auth-service
sleep 3
docker exec enterprise_auth_service alembic upgrade head

# 5. Start remaining services
echo "🌐 Starting all remaining services..."
docker compose up -d

# 6. Wait for services to be healthy
echo "⏳ Waiting for all services to be healthy..."
sleep 10

# 7. Check status
echo "✅ Deployment complete! Checking service status..."
docker compose ps

echo ""
echo "🎉 Application is ready!"
echo "   Frontend: http://localhost:5173"
echo "   API Gateway: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
echo "📧 Admin credentials:"
echo "   Email: admin@example.com"
echo "   Password: Admin123!"
echo ""