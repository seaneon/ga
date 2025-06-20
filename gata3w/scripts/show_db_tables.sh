#!/bin/bash

# scripts/show_db_tables.sh
# Displays all tables in the FIRM database (public schema).
# Loads secrets from .env using set -a; source .env; set +a.
# Connects to PostgreSQL using credentials from .env (PG_USER, PG_PASSWORD, etc.).
# Designed for Go 1.24.2 linux/amd64, with public usability.
# Prerequisites: PostgreSQL, .env with PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DB.

# Exit on error
set -e

echo "✅ Listing tables in FIRM database..."

# Check for PostgreSQL
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL (psql) not found. Install it: sudo apt install postgresql"
    exit 1
fi

# Check for .env
if [ ! -f ".env" ]; then
    echo "❌ .env not found. Copy .env.example to .env and fill in credentials."
    exit 1
fi

# Load secrets from .env
echo "🔑 Loading secrets from .env..."
set -a
source .env
set +a

# Validate environment variables
if [ -z "$PG_USER" ] || [ -z "$PG_PASSWORD" ] || [ -z "$PG_HOST" ] || [ -z "$PG_PORT" ] || [ -z "$PG_DB" ]; then
    echo "❌ Missing required environment variables (PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DB)."
    exit 1
fi

# List tables using psql
echo "📋 Tables in database $PG_DB (public schema):"
PGPASSWORD=$PG_PASSWORD psql -U $PG_USER -h $PG_HOST -p $PG_PORT -d $PG_DB -c "\dt" | grep table || {
    echo "❌ Failed to list tables. Check .env credentials or ensure database is initialized."
    exit 1
}

echo "✅ Done listing tables."
