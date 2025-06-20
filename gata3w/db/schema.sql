-- TABLE email_verifications
CREATE TABLE IF NOT EXISTS email_verifications (
    email VARCHAR(255) PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    token_count INTEGER NOT NULL DEFAULT 0,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    last_token VARCHAR(64),
    last_ip VARCHAR(45),
    last_attempt TIMESTAMP,
    last_blocked TIMESTAMP,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email);
CREATE INDEX IF NOT EXISTS idx_email_verifications_last_blocked ON email_verifications(last_blocked);

-- TABLE tokens
CREATE TABLE IF NOT EXISTS tokens (
    token_id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    status VARCHAR(20) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens(email);

-- TABLE ip_activity
CREATE TABLE IF NOT EXISTS ip_activity (
    ip_hex VARCHAR(45) PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    token_requests INTEGER NOT NULL DEFAULT 0,
    inbound_attempts INTEGER NOT NULL DEFAULT 0,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_blocked TIMESTAMP,
    expires_at TIMESTAMP,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_ip_activity_ip_hex ON ip_activity(ip_hex);
CREATE INDEX IF NOT EXISTS idx_ip_activity_last_seen ON ip_activity(last_seen);

-- TABLE banned_subnets
CREATE TABLE IF NOT EXISTS banned_subnets (
    subnet_hex VARCHAR(45) NOT NULL,
    cidr INTEGER NOT NULL,
    reason TEXT,
    banned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    hits INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subnet_hex, cidr)
);
CREATE INDEX IF NOT EXISTS idx_banned_subnets_subnet_hex ON banned_subnets(subnet_hex);

-- TABLE admin_emails
CREATE TABLE IF NOT EXISTS admin_emails (
    email VARCHAR(255) PRIMARY KEY,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(255),
    expires_at TIMESTAMP,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_emails_email ON admin_emails(email);

-- TABLE admin_events
CREATE TABLE IF NOT EXISTS admin_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action VARCHAR(50) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    target TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_events_timestamp ON admin_events(timestamp);

-- TABLE settings
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);