# WARNING: This will DELETE ALL DATA in the firm database!
# Prerequisites: PostgreSQL, .env with PG_USER, PG_PASSWORD, etc., firm.conf.

# Exit on error
set -e

# Safety prompt to prevent accidental execution
echo "WARNING: This will DELETE ALL DATA in the firm database!"
echo "Type 'eraseDB' to continue or press Ctrl+C to abort:"
read -r confirm
if [ "$confirm" != "eraseDB" ]; then
    echo "❌ Aborted: Input did not match 'eraseDB'."
    exit 1
fi

echo "✅ Resetting FIRM database for test mode..."

# Check for PostgreSQL
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL (psql) not found. Install it: sudo apt install postgresql"
    exit 1
fi

# Check for Go
if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Install Go 1.24.2: https://go.dev/dl/"
    exit 1
fi
go_version=$(go version | grep -o "go1.24.2")
if [ "$go_version" != "go1.24.2" ]; then
    echo "❌ Requires Go 1.24.2 linux/amd64, found: $(go version)"
    exit 1
fi

# Check for .env
if [ ! -f ".env" ]; then
    echo "❌ .env not found. Copy .env.example to .env and fill in credentials."
    exit 1
fi

# Check for firm.conf
if [ ! -f "firm.toml" ]; then
    echo "❌ firm.conf not found. Create it with [settings] section."
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

# Drop database using psql
echo "🗑️  Dropping database $PG_DB..."
PGPASSWORD=$PG_PASSWORD psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -c "DROP DATABASE IF EXISTS \"$PG_DB\";" || {
    echo "❌ Failed to drop database. Check credentials in .env."
    exit 1
}

# --- ADD THIS SECTION ---
# Create database using psql
echo "✨ Creating database $PG_DB..."
PGPASSWORD=$PG_PASSWORD psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" -d postgres -c "CREATE DATABASE \"$PG_DB\" OWNER \"$PG_USER\";" || {
    echo "❌ Failed to create database. Ensure user '$PG_USER' has CREATE DATABASE privileges."
    exit 1
}
