# FIRM
Passwordless Authentication Server

FIRM is a passwordless authentication server based on draft-feeser-firm-auth-08. It uses Mailgun for inbound email webhooks, Gmail IMAP for small setups, and PostgreSQL for storage. This guide provides bash commands to install and set up FIRM on Linux/amd64 with Go 1.24.2.

## Prerequisites

- Go 1.24.2 linux/amd64
- PostgreSQL 15 or later
- Git
- Mailgun account (for webhooks, configured later)
- Gmail account (for IMAP fallback, configured later)

## Installation


1. **Clone the repo**

    ```bash
    git clone https://github.com/alta3/github-actions-the-alta3-way.git
    cd ~/github-actions-the-alta3-way
    ```

0. **Check your Go version**

    ```bash
    go version # Should output go1.24.2 linux/amd64
    ```

2. **Install Go** (if not installed)

    ```bash
    ./scripts/go_install.sh 
    ```

4. **Install dependencies**

    ```bash
    go mod tidy
    ```

## Environment Setup

Store secrets (e.g., PostgreSQL credentials) in a `.env` file, ignored by `.gitignore` for security. Edit `.env` with `vim` to set your credentials.

5. **Create a `.env` file**

    ```bash
    cat <<EOF > .env
    PG_USER=postgres
    PG_PASSWORD=password
    PG_HOST=localhost
    PG_PORT=5432
    PG_DB=firm
    FIRM_USER=firmuser
    FIRM_PASSWORD=firmpass
    EOF
    ```

0. Edit the .env file

    ```bash
    vim .env
    ```

    > Edit with your superuser credentials, e.g., **PG_USER=roadmatric**, **PG_PASSWORD=roadmatrix-4d**
      Keep **FIRM_USER=firmuser**, **FIRM_PASSWORD=firmpass** or set custom values

6. **Export `.env` variables**

    Make `.env` variables available to subsequent commands:

    ```bash
    set -a; source .env; set +a
    echo Verifing variables:
    printenv | grep PG
    printenv | grep FIRM
    ```

7. **Verify `.gitignore`**

    The repo includes `.gitignore` with `.env` to prevent committing secrets. Check it:

    ```bash
    cat .gitignore | grep .env
    ```

## Database Setup

Set up the `firm` database with a dedicated user for security. Use exported `.env` variables to minimize errors. Assumes a PostgreSQL superuser (e.g., `roadmatric` or `postgres`) defined in `.env`.

8. **Install PostgreSQL** (if not installed)

    ```bash
    sudo apt update
    sudo apt install postgresql postgresql-contrib -y
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    ```

9. **Create a dedicated user and database**

    Create `FIRM_USER` and `PG_DB` database using `.env` variables:

    ```bash
    # Uses PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, FIRM_USER, FIRM_PASSWORD from .env
    sudo -u postgres psql <<EOF
    CREATE USER $FIRM_USER WITH PASSWORD '$FIRM_PASSWORD';
    CREATE DATABASE $PG_DB OWNER $FIRM_USER;
    GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $FIRM_USER;
    EOF

    if [ $? -ne 0 ]; then
        echo "Error: Failed to create user or database. Check .env credentials."
    fi
    ```

0. Test connection as firmuser

    ```bash
    PGPASSWORD=$FIRM_PASSWORD psql -U $FIRM_USER -h $PG_HOST -p $PG_PORT -d $PG_DB
    ```

    > Exit with `exit`

10. **Update `.env` with database credentials**

    Edit `.env` to use the new user for server operations:

    ```bash
    vim .env
    # Set: PG_USER=$FIRM_USER, PG_PASSWORD=$FIRM_PASSWORD
    # Re-export variables
    set -a; source .env; set +a
    ```

11. **Initialize the database**

    Run the server to create tables and apply the schema:

    ```bash
    go run main.go
    ```

## Testing

12. **Reset database for schema changes** (test mode)

    Drop and reinitialize the database for schema updates. Requires typing `eraseDB` to confirm:

    ```bash
    ./scripts/reset_db.sh
    # WARNING: DELETES ALL DATA! Type 'eraseDB' when prompted.
    ```

## Configuration

13. **Edit `firm.conf`**

    Configure non-sensitive settings:

    ```bash
    vim firm.conf
    # Example settings:
    # [settings]
    # cleanup_interval = "10s"
    # inbound_method = "webhook"
    ```

## Running

**To be completed with instructions for running the server.**

## Mailgun/Gmail Setup

**To be completed with steps for configuring webhooks and IMAP.**

## Troubleshooting

**To be added with common issues and solutions.**
