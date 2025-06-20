package main

import (
	"context"
	"fmt"
	"html/template" // Import for HTML templates
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn" // Import for pgconn.CommandTag
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"github.com/google/uuid"
)

// schemaSQL defines the PostgreSQL database schema for the FIRM protocol.
// This will be executed on application startup to ensure tables exist.
const schemaSQL = `
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

-- Initial settings population if not exists.
-- Corrected syntax: Each INSERT statement must be complete and separated by a semicolon.
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('rate_limit_tokens_per_hour', '10', 'Maximum token requests per hour per email/IP.', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('email_retention_period', '1095d', 'How long to retain email verification records (e.g., 365d, 1y).', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('cleanup_interval', '10s', 'Frequency of the cleanup loop (e.g., 10s, 1m).', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('send_welcome_email', 'true', 'Whether to send an optional welcome email after verification.', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('firm_server_email', 'firmserver@example.com', 'The email address that FIRM expects verification emails to be sent to.', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value, description, updated_at, updated_by) VALUES
('jwt_secret_key', 'your_super_secret_jwt_key_please_change_this_in_prod', 'Secret key for signing JWTs. MUST BE SECURE AND ROTATED.', NOW(), 'system') ON CONFLICT (key) DO NOTHING;
`

// Global database connection pool
var db *pgxpool.Pool

// Setting holds application configuration settings.
type Setting struct {
	Key         string    `db:"key"`
	Value       string    `db:"value"`
	Description string    `db:"description"`
	UpdatedAt   time.Time `db:"updated_at"`
	UpdatedBy   string    `db:"updated_by"`
}

// Global variable for FIRM_SERVER_EMAIL, set from config
var firmServerEmail string

// Global variable for JWT secret key, updated from settings
var jwtSecretKey []byte

// Regex for FIRM token extraction
var firmTokenRegex = regexp.MustCompile(`FIRM-TOKEN:([A-Za-z0-9-]+)`)


// IPNormalization(inboundMessage)
// → Extracts IP (e.g., from c.ClientIP())
// → Returns hex string:
//     • 8 chars for IPv4 (e.g., 192.168.1.1 → C0A80101)
//     • 32 chars for IPv6 (e.g., ::1 → 00000000000000000000000000000001)
//     • NOTE: hex IPs are *not* CIDR aware. Use separately for CIDR matching.
func IPNormalization(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return fmt.Sprintf("%02X%02X%02X%02X", ipv4[0], ipv4[1], ipv4[2], ipv4[3]), nil
	}
	// For IPv6, we need to handle the 16 bytes
	return fmt.Sprintf("%X", ip.To16()), nil
}

// IsBlockedIP(ipStr string)
// → Calls IPNormalization()
// → Returns true if:
//     • IP is in banned_subnets table
//     • OR ip_activity.blocked == true
func IsBlockedIP(c *gin.Context) bool {
	ipStr := c.ClientIP()
	ipHex, err := IPNormalization(ipStr)
	if err != nil {
		log.Printf("ERROR: Malformed IP %s for blocking check: %v", ipStr, err)
		// Log to ip_activity with notes "malformed" and increment inbound_attempts (handled by middleware)
		return true // Treat malformed IPs as blocked
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if IP is in banned_subnets table
	var count int
	err = db.QueryRow(ctx, "SELECT COUNT(*) FROM banned_subnets WHERE subnet_hex = $1", ipHex).Scan(&count)
	if err == nil && count > 0 {
		// Increment hits for the banned subnet (async or in a separate goroutine if performance critical)
		go func() {
			_, err := db.Exec(context.Background(), "UPDATE banned_subnets SET hits = hits + 1 WHERE subnet_hex = $1", ipHex)
			if err != nil {
				log.Printf("ERROR: Could not increment banned subnet hits for %s: %v", ipHex, err)
			}
		}()
		log.Printf("IP %s blocked by direct subnet ban.", ipStr)
		return true
	}

	// Check if ip_activity.blocked is true
	var blocked bool
	err = db.QueryRow(ctx, "SELECT blocked FROM ip_activity WHERE ip_hex = $1", ipHex).Scan(&blocked)
	if err == nil && blocked {
		log.Printf("IP %s blocked by ip_activity status.", ipStr)
		return true
	} else if err != nil && err != pgx.ErrNoRows {
		log.Printf("ERROR: Database error checking ip_activity for %s: %v", ipStr, err)
		return true // Fail safe: block if database is having issues
	}

	return false
}

// NormalizeCIDR(ipStr string, cidr int) → subnet
// → Converts any IP string and CIDR into the proper network base
// → e.g., "192.168.2.123" + /24 → "C0A80200" (hex of 192.168.2.0)
// → Used for inserts and IP-in-subnet checks
// NOTE: CIDR always wins: store corrected network base even if input IP is not aligned
func NormalizeCIDR(ipStr string, cidr int) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Calculate the network address for the given CIDR
	var network *net.IPNet
	if ip.To4() != nil {
		if cidr < 0 || cidr > 32 {
			return "", fmt.Errorf("invalid IPv4 CIDR %d", cidr)
		}
		// Create a mock CIDR string and parse it
		_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", ip.To4().String(), cidr))
	} else { // Assume IPv6
		if cidr < 0 || cidr > 128 {
			return "", fmt.Errorf("invalid IPv6 CIDR %d", cidr)
		}
		// Create a mock CIDR string and parse it
		_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", ip.To16().String(), cidr))
	}

	return IPNormalization(network.IP.String())
}


// TimeOutHandler(db *pgxpool.Pool)
// All expired bans, rows, etc cleared
// Basically this is garbage collection and releasing users from ratelimit jail
// Runs every 'cleanup_interval' seconds and MUST be very efficent
func TimeOutHandler(db *pgxpool.Pool) {
	log.Println("Cleanup routine started.")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Give cleanup 30s
	defer cancel()

	now := time.Now().UTC()

	// 1. Delete expired or unused FIRM tokens
	// FIRM tokens expire within 15-60 minutes. Delete if expired or if "issued" and older than 1 hour.
	cmdTag, err := db.Exec(ctx, "DELETE FROM tokens WHERE expires_at < $1 OR (status = 'issued' AND created_at < $2)", now, now.Add(-1*time.Hour))
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to delete expired/unused tokens: %v", err)
	} else {
		log.Printf("Cleanup: Deleted %d expired/unused tokens.", cmdTag.RowsAffected())
	}

	// 2. Delete expired email verifications
	retentionPeriodStr := viper.GetString("settings.email_retention_period")
	retentionDuration, err := time.ParseDuration(retentionPeriodStr)
	if err != nil {
		log.Printf("ERROR: Cleanup - invalid email_retention_period '%s', defaulting to 1095d: %v", retentionPeriodStr, err)
		retentionDuration = 1095 * 24 * time.Hour // 3 years
	}
	cmdTag, err = db.Exec(ctx, "DELETE FROM email_verifications WHERE expires_at < $1 OR (verified = FALSE AND last_attempt < $2)", now, now.Add(-retentionDuration))
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to delete expired email verifications: %v", err)
	} else {
		log.Printf("Cleanup: Deleted %d expired email verifications.", cmdTag.RowsAffected())
	}

	// 3. Delete expired IP activity records
	cmdTag, err = db.Exec(ctx, "DELETE FROM ip_activity WHERE expires_at < $1", now)
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to delete expired IP activity: %v", err)
	} else {
		log.Printf("Cleanup: Deleted %d expired IP activity records.", cmdTag.RowsAffected())
	}

	// 4. Delete expired banned subnets
	cmdTag, err = db.Exec(ctx, "DELETE FROM banned_subnets WHERE expires_at IS NOT NULL AND expires_at < $1", now)
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to delete expired banned subnets: %v", err)
	} else {
		log.Printf("Cleanup: Deleted %d expired banned subnets.", cmdTag.RowsAffected())
	}

	// 5. Delete expired admin emails
	cmdTag, err = db.Exec(ctx, "DELETE FROM admin_emails WHERE expires_at IS NOT NULL AND expires_at < $1", now)
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to delete expired admin emails: %v", err)
	} else {
		log.Printf("Cleanup: Deleted %d expired admin emails.", cmdTag.RowsAffected())
	}

	// 6. Release temporary blocks on IP activity (rate limiting jail)
	// If an IP was last blocked more than 10 minutes ago, unblock it.
	cmdTag, err = db.Exec(ctx, "UPDATE ip_activity SET blocked = FALSE, last_blocked = NULL WHERE blocked = TRUE AND last_blocked < $1", now.Add(-10*time.Minute))
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to release IP blocks: %v", err)
	} else {
		log.Printf("Cleanup: Released %d IP blocks.", cmdTag.RowsAffected())
	}

	// Log cleanup completion to admin_events
	_, err = db.Exec(ctx,
		"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
		now, "cleanup_run", "system", "database", "Cleanup routine executed.",
	)
	if err != nil {
		log.Printf("ERROR: Cleanup - failed to log admin event: %v", err)
	}
	log.Println("Cleanup routine finished.")
}


// initDB initializes the PostgreSQL database connection and creates tables if they don't exist.
func initDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pgURL := viper.GetString("database.url")
	if pgURL == "" {
		log.Fatalf("FATAL: database.url not found in configuration.")
	}

	var err error
	db, err = pgxpool.New(ctx, pgURL)
	if err != nil {
		log.Fatalf("FATAL: Unable to connect to database: %v", err)
	}

	err = db.Ping(ctx)
	if err != nil {
		log.Fatalf("FATAL: Failed to ping database: %v", err)
	}
	log.Println("✅ Successfully connected to the PostgreSQL database.")

	// Execute schema SQL to create tables and insert initial settings
	// We use a single batch query for schemaSQL. If there are multiple statements
	// within schemaSQL, db.ExecContext is sufficient for pgx as it handles
	// multiple statements if they are separated by semicolons correctly.
	_, err = db.Exec(ctx, schemaSQL)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize database schema: %v", err)
	}
	log.Println("✅ Database schema initialized successfully.")

	// Load initial global settings from the database
	firmServerEmail = getSetting("firm_server_email", "firmserver@example.m")
	jwtSecretKey = []byte(getSetting("jwt_secret_key", "your_super_secret_jwt_key_please_change_this_in_prod"))
	if string(jwtSecretKey) == "your_super_secret_jwt_key_please_change_this_in_prod" {
		log.Println("WARNING: Using default JWT secret key. Please change 'jwt_secret_key' in settings table or .env file.")
	}
}


// getSetting retrieves a setting value from the database.
// It uses a mutex to ensure thread-safe access if we were caching settings.
// For now, it directly queries the DB.
func getSetting(key, defaultValue string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var value string
	err := db.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1", key).Scan(&value)
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("ERROR: Could not fetch setting '%s': %v. Using default.", key, err)
		}
		return defaultValue
	}
	return value
}

// updateSettingInDB updates a setting in the database.
func updateSettingInDB(ctx context.Context, key, value, updatedBy string) error {
	_, err := db.Exec(ctx,
		`INSERT INTO settings (key, value, description, updated_at, updated_by)
         VALUES ($1, $2, $3, NOW(), $4)
         ON CONFLICT (key) DO UPDATE SET
             value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by;`,
		key, value, fmt.Sprintf("Updated by %s", updatedBy), updatedBy,
	)
	return err
}


// --- Core Helper Functions ---

// GenerateFIRMToken creates a unique FIRM-TOKEN string.
func GenerateFIRMToken() string {
	// A simple UUID-based token for demonstration.
	// Format: FIRM-TOKEN:XXXX-YYYY-ZZZZ (UUID v4 produces 32 hex chars, so we take a portion)
	id := strings.ReplaceAll(uuid.New().String(), "-", "")
	return fmt.Sprintf("FIRM-TOKEN:%s-%s-%s", id[0:4], id[4:8], id[8:12])
}

// ExtractFirstToken(subject, body string)
// Parses email subject/body for a FIRM-TOKEN.
func ExtractFirstToken(subject, body string) string {
	// Try subject first
	if matches := firmTokenRegex.FindStringSubmatch(subject); len(matches) > 0 { // Check len(matches) > 0 instead of > 1
		return matches[0] // Return the full matched string, including prefix
	}
	// Then try body
	if matches := firmTokenRegex.FindStringSubmatch(body); len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// CustomClaims for JWT
type Claims struct {
	Email string `json:"sub"`
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// GenerateJWT(email, scope string)
// Creates a signed JWT refresh token.
func GenerateJWT(email, scope string) (string, error) {
	now := time.Now().UTC()
	expirationTime := now.Add(90 * 24 * time.Hour) // 90 days expiration

	jti := uuid.New().String()

	claims := &Claims{
		Email: email,
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "firm.example.com",
			Subject:   email,
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Insert jti into tokens table
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = db.Exec(ctx,
		"INSERT INTO tokens (token_id, email, created_at, expires_at, status) VALUES ($1, $2, $3, $4, $5)",
		jti, email, now, expirationTime, "issued",
	)
	if err != nil {
		return "", fmt.Errorf("failed to store JWT jti in DB: %w", err)
	}

	return tokenString, nil
}


// ValidateJWT(token string)
// Decodes and validates a JWT, checking its signature, claims, and revocation status.
func ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("JWT is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check jti in tokens table and status
	var status string
	var storedEmail string
	err = db.QueryRow(ctx, "SELECT status, email FROM tokens WHERE token_id = $1", claims.ID).Scan(&status, &storedEmail)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("JWT jti not found in tokens table")
		}
		return nil, fmt.Errorf("database error checking JWT jti: %w", err)
	}

	if status == "revoked" {
		return nil, fmt.Errorf("JWT jti is revoked")
	}
	if storedEmail != claims.Email {
		return nil, fmt.Errorf("JWT subject mismatch with stored email")
	}

	return claims, nil
}

// RevokeJWT(jti string)
// Marks a JWT's JTI as revoked in the database.
func RevokeJWT(jti string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmdTag, err := db.Exec(ctx, "UPDATE tokens SET status = 'revoked', used_at = $1 WHERE token_id = $2", time.Now().UTC(), jti)
	if err != nil {
		return fmt.Errorf("failed to revoke JWT in DB: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("no JWT found with jti: %s", jti)
	}

	// Log to admin_events
	_, err = db.Exec(ctx,
		"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
		time.Now().UTC(), "revoke_jwt", "system", jti, "JWT revoked by server",
	)
	if err != nil {
		log.Printf("ERROR: Failed to log revoke_jwt event: %v", err)
	}
	return nil
}


// Mock external services
func verifySPF(email, ip string) bool {
	log.Printf("MOCK: Performing SPF check for %s from %s - Result: PASS", email, ip)
	return true
}

func verifyDKIM(headers map[string]string) bool {
	log.Printf("MOCK: Performing DKIM check for headers - Result: PASS")
	return true
}

func sendWelcomeEmail(email string) {
	log.Printf("MOCK: Sending welcome email to %s", email)
	// Placeholder for actual email sending logic (e.g., SMTP, Mailgun API)
}

func sendWebSocketEvent(eventType, email, jwtToken string, timestamp time.Time) {
	log.Printf("MOCK: Sending WebSocket event: %s for %s with JWT (first 10 chars): %s... at %s", eventType, email, jwtToken[:10], timestamp.Format(time.RFC3339))
	// Placeholder for actual WebSocket/SSE communication
}

// --- Middleware ---

// ipActivityMiddleware logs and updates IP activity for each request.
// It also tracks potential blocks but does NOT enforce them; enforcement is left to routes.
func ipActivityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ipStr := c.ClientIP()
		ipHex, err := IPNormalization(ipStr)
		if err != nil {
			log.Printf("ERROR: Malformed IP in middleware: %s. Notes: malformed", ipStr)
			// For malformed IPs, we'll still log to ip_activity, but won't associate with specific token/inbound attempts initially
			// The draft implies malformed IPs should increment ip_activity.inbound_attempts
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err := db.Exec(ctx,
					`INSERT INTO ip_activity (ip_hex, first_seen, last_seen, inbound_attempts, notes)
                     VALUES ($1, $2, $3, 1, 'malformed')
                     ON CONFLICT (ip_hex) DO UPDATE SET
                         last_seen = EXCLUDED.last_seen,
                         inbound_attempts = ip_activity.inbound_attempts + 1,
                         notes = 'malformed';`,
					ipHex, time.Now().UTC(), time.Now().UTC(),
				)
				if err != nil {
					log.Printf("ERROR: Failed to update ip_activity for malformed IP %s: %v", ipStr, err)
				}
			}()
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var tokenRequests, inboundAttempts int
		var firstSeen time.Time
		var blocked bool
		var lastSeen time.Time

		// Query existing record
		err = db.QueryRow(ctx, "SELECT token_requests, inbound_attempts, first_seen, blocked, last_seen FROM ip_activity WHERE ip_hex = $1", ipHex).Scan(
			&tokenRequests, &inboundAttempts, &firstSeen, &blocked, &lastSeen,
		)

		if err != nil && err != pgx.ErrNoRows {
			log.Printf("ERROR: Database error in ipActivityMiddleware for %s: %v", ipStr, err)
			c.Next() // Allow request to proceed, but don't track activity
			return
		}

		now := time.Now().UTC()
		if err == pgx.ErrNoRows {
			// New IP, insert
			_, err = db.Exec(ctx,
				`INSERT INTO ip_activity (ip_hex, first_seen, last_seen, token_requests, inbound_attempts, blocked, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				ipHex, now, now, 0, 0, false, now.Add(24*time.Hour), // Expire in 1 day for initial entry
			)
			if err != nil {
				log.Printf("ERROR: Failed to insert new IP activity for %s: %v", ipStr, err)
			}
		} else {
			// Existing IP, update
			// Note: token_requests and inbound_attempts are incremented by specific routes.
			// This middleware just updates last_seen and potentially 'blocked' status
			_, err = db.Exec(ctx,
				`UPDATE ip_activity SET last_seen = $1 WHERE ip_hex = $2`,
				now, ipHex,
			)
			if err != nil {
				log.Printf("ERROR: Failed to update existing IP activity for %s: %v", ipStr, err)
			}
		}

		c.Next()
	}
}

// autoIPBanMiddleware checks and updates IP ban status based on recent activity.
// It also unbans IPs after 10 minutes of "forgiveness".
func autoIPBanMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ipStr := c.ClientIP()
		ipHex, err := IPNormalization(ipStr)
		if err != nil {
			c.Next() // Malformed IPs handled by IPActivityMiddleware's logging and IPNormalization's block on check
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var tokenRequests, blockedCount int
		var lastBlocked *time.Time // Use pointer for nullable timestamp
		var blocked bool

		// Retrieve current IP activity data
		err = db.QueryRow(ctx, "SELECT token_requests, blocked, blocked_count, last_blocked FROM ip_activity WHERE ip_hex = $1", ipHex).Scan(
			&tokenRequests, &blocked, &blockedCount, &lastBlocked,
		)

		if err != nil {
			if err == pgx.ErrNoRows {
				// IP not in ip_activity, it will be handled by IPActivityMiddleware for future requests.
				// No rate limit check on first seen.
			} else {
				log.Printf("ERROR: Database error in autoIPBanMiddleware for %s: %v", ipStr, err)
			}
			c.Next()
			return
		}

		now := time.Now().UTC()

		// Unban if last_blocked was more than 10 minutes ago
		if blocked && lastBlocked != nil && now.Sub(*lastBlocked) > 10*time.Minute {
			log.Printf("Unbanning IP %s (hex: %s) due to forgiveness period.", ipStr, ipHex)
			_, err := db.Exec(ctx, "UPDATE ip_activity SET blocked = FALSE, last_blocked = NULL WHERE ip_hex = $1", ipHex)
			if err != nil {
				log.Printf("ERROR: Failed to unban IP %s: %v", ipStr, err)
			}
			blocked = false // Update local state
		}

		// Check if token_requests in last 10 minutes >= threshold
		// NOTE: This check needs improvement. 'token_requests' is a cumulative counter.
		// A more robust rate limiting would involve tracking requests per time window (e.g., using Redis or a dedicated rate-limiting table).
		// For now, we'll apply a simple check based on a high cumulative count.
		// The draft suggests rate_limit_attempts_per_hour. We'll simulate a strict temporary ban.

		rateLimitAttemptsPerHour, _ := strconv.Atoi(getSetting("rate_limit_attempts_per_hour", "10"))
		// We'll use the cleanup routine to reset the 'blocked' status, making this a temporary ban.
		// If the current token_requests count exceeds double the per-hour limit, block.
		// This is a crude approximation until per-hour tracking is added to ip_activity or a separate mechanism.
		// The `TimeOutHandler` (Cleanup) will handle unblocking if `last_blocked` is old enough.

		// TEMPORARY LOGIC: If total token_requests exceeds double the per-hour limit, block.
		// This is a crude approximation until per-hour tracking is added to ip_activity or a separate mechanism.
		if tokenRequests > 2*rateLimitAttemptsPerHour && !blocked {
			log.Printf("Automatically blocking IP %s (hex: %s) due to excessive token requests (%d).", ipStr, ipHex, tokenRequests)
			_, err := db.Exec(ctx,
				`UPDATE ip_activity SET blocked = TRUE, blocked_count = blocked_count + 1, last_blocked = $1 WHERE ip_hex = $2`,
				now, ipHex,
			)
			if err != nil {
				log.Printf("ERROR: Failed to automatically block IP %s: %v", ipStr, err)
			}
			// Insert a /32 or /128 ban into banned_subnets for this specific IP.
			go func() {
				var cidr int
				if ip := net.ParseIP(ipStr); ip.To4() != nil {
					cidr = 32
				} else {
					cidr = 128
				}
				subnetHex, err := NormalizeCIDR(ipStr, cidr)
				if err != nil {
					log.Printf("ERROR: Could not normalize CIDR for auto-ban: %v", err)
					return
				}
				_, err = db.Exec(context.Background(),
					`INSERT INTO banned_subnets (subnet_hex, cidr, reason, banned_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (subnet_hex, cidr) DO UPDATE SET
                         reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at, expires_at = EXCLUDED.expires_at, hits = banned_subnets.hits + 1;`,
					subnetHex, cidr, "Auto-rate-limit exceeded", now, now.Add(10*time.Minute), // Ban for 10 minutes initially
				)
				if err != nil {
					log.Printf("ERROR: Failed to insert auto-ban into banned_subnets for %s/%d: %v", subnetHex, cidr, err)
				}
			}()
		}
		c.Next()
	}
}


func main() {
	// Dummy use of imported packages to prevent "imported and not used" errors
	// These are here to satisfy the Go compiler's strictness about unused imports
	// which can happen with indirect usage (e.g., Gin's template engine or type definitions).
	_ = template.HTMLEscapeString // Use a function from html/template
	_ = pgconn.CommandTag{}       // Use a type from pgconn


	// ✅ Load environment variables from .env or system and log success
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on system environment variables.")
	} else {
		log.Println("✅ .env file loaded successfully.")
	}

	// ✅ Read viper firm.conf file and log success
	viper.SetConfigName("firm") // name of config file (without extension)
	viper.SetConfigType("toml")  // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")     // optionally look for config in the working directory
	viper.AddConfigPath("/etc/firm/") // path to look for the config file in

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Fatalf("FATAL: Config file firm.toml not found. Please create one.")
		} else {
			log.Fatalf("FATAL: Error reading config file: %v", err)
		}
	}
	log.Println("✅ Configuration file firm.toml loaded successfully.")

	// Log all configuration values for debugging
	log.Println("--- Configuration Settings ---")
	for _, key := range viper.AllKeys() {
		log.Printf("  %s: %v", key, viper.Get(key))
	}
	log.Println("----------------------------")

	// ✅ Initialize the PostgreSQL database and all tables and log success
	initDB()
	defer db.Close() // Ensure database connection is closed when main exits

	// Start the cleanup routine in a separate goroutine
	cleanupIntervalStr := viper.GetString("settings.cleanup_interval")
	cleanupInterval, err := time.ParseDuration(cleanupIntervalStr)
	if err != nil {
		log.Printf("ERROR: Invalid cleanup_interval '%s', defaulting to 10s: %v", cleanupIntervalStr, err)
		cleanupInterval = 10 * time.Second
	}
	log.Printf("Starting cleanup routine every %v...", cleanupInterval)
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			TimeOutHandler(db)
		}
	}()

	// ✅ Initialize the Gin router and attach middleware and log success
	r := gin.Default()
	log.Println("✅ Gin router initialized.")

	// Configure template loading
	// Load all templates including the layout
	// IMPORTANT: When you have a base layout and content templates, Gin's LoadHTMLGlob
	// will parse all files. Then, when calling c.HTML, you specify the name of the base layout template
	// (e.g., "base.html") and the data will include ContentTemplate to tell base.html what content to render.
	r.LoadHTMLGlob("templates/**/*.html")
	// Configure static file serving
	r.Static("/static", "./static")
	// Favicon.ico specific handler
	r.StaticFile("/favicon.ico", "./static/favicon.ico")


	// ✅ Middleware: IP Logging and auto IP Ban (or unban)
	// These run for every incoming request
	r.Use(ipActivityMiddleware())
	r.Use(autoIPBanMiddleware())
	log.Println("✅ IP Logging and Auto IP Ban middleware attached.")


	// Define API routes
	// A sync.Mutex to protect temp_firm_tokens for /test routes
	var tempTokensMutex sync.Mutex
	tempFirmTokens := make(map[string]struct {
		Email     string
		CreatedAt time.Time
		ExpiresAt time.Time
	})

	// Non-admin API routes (no middleware needed here as they are public or handled internally)
	r.POST("/test", func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if IsBlockedIP(c) {
			c.JSON(403, gin.H{"error": "IP blocked"})
			return
		}

		token := GenerateFIRMToken()
		// Store in-memory for /test/inbound to consume
		tempTokensMutex.Lock()
		tempFirmTokens[token] = struct {
			Email     string
			CreatedAt time.Time
			ExpiresAt time.Time
		}{
			Email:     req.Email,
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour), // 1 hour for test tokens
		}
		tempTokensMutex.Unlock()

		c.JSON(200, gin.H{
			"message": fmt.Sprintf("Send an email from %s to %s with token %s in the subject or body.", req.Email, firmServerEmail, token),
			"token":   token,
		})
	})

	// /test/inbound route (POST) - For simulating inbound verification
	r.POST("/test/inbound", func(c *gin.Context) {
		var req struct {
			Email   string `json:"email" binding:"required,email"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
			Headers map[string]string `json:"headers"` // Mock headers
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if IsBlockedIP(c) {
			c.JSON(403, gin.H{"error": "IP blocked"})
			return
		}

		// Mock SPF/DKIM checks for testing
		if !verifySPF(req.Email, c.ClientIP()) {
			c.JSON(403, gin.H{"error": "SPF check failed. See https://firm.example.com/blog/spf-dkim"})
			return
		}
		if !verifyDKIM(req.Headers) {
			c.JSON(403, gin.H{"error": "DKIM check failed. See https://firm.example.com/blog/spf-dkim"})
			return
		}

		mailFromDomain := strings.ToLower(strings.Split(req.Email, "@")[1])
		fromHeader, ok := req.Headers["From"] // Get "From" header from the map
		if !ok || fromHeader == "" {
			c.JSON(403, gin.H{"error": "Missing 'From' header for domain matching"})
			return
		}
		fromHeaderParts := strings.Split(fromHeader, "@")
		if len(fromHeaderParts) < 2 {
			c.JSON(403, gin.H{"error": "Malformed 'From' header for domain matching"})
			return
		}
		fromHeaderDomain := strings.ToLower(fromHeaderParts[1])

		if mailFromDomain != fromHeaderDomain {
			c.JSON(403, gin.H{"error": "MAIL FROM and From header domains mismatch"})
			return
		}

		// CORRECTED: Extract token from req.Subject or req.Body
		reqToken := ExtractFirstToken(req.Subject, req.Body)
		if reqToken == "" || !strings.HasPrefix(reqToken, "FIRM-TOKEN:") {
			c.JSON(400, gin.H{"error": "Invalid or missing token"})
			return
		}

		tempTokensMutex.Lock()
		defer tempTokensMutex.Unlock()
		// CORRECTED: Use reqToken to access tempFirmTokens map
		storedToken, exists := tempFirmTokens[reqToken]

		if !exists || storedToken.Email != req.Email {
			c.JSON(403, gin.H{"error": "Invalid or expired token"})
			return
		}
		if storedToken.ExpiresAt.Before(time.Now().UTC()) {
			delete(tempFirmTokens, reqToken) // CORRECTED: Delete using reqToken
			c.JSON(400, gin.H{"error": "Token expired"})
			return
		}

		delete(tempFirmTokens, reqToken) // CORRECTED: Delete using reqToken
		c.JSON(200, gin.H{"message": "Test token verified"})
	})

	// ✅ /signup route (POST: {email})
	r.POST("/signup", func(c *gin.Context) {
		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		if IsBlockedIP(c) {
			c.JSON(403, gin.H{"error": "IP blocked"})
			return
		}

		var emailVerification struct {
			TokenCount  int       `db:"token_count"`
			LastAttempt *time.Time `db:"last_attempt"`
			LastBlocked *time.Time `db:"last_blocked"`
		}

		// Retrieve current email verification data
		err := db.QueryRow(ctx, "SELECT token_count, last_attempt, last_blocked FROM email_verifications WHERE email = $1", req.Email).Scan(
			&emailVerification.TokenCount, &emailVerification.LastAttempt, &emailVerification.LastBlocked,
		)

		if err != nil && err != pgx.ErrNoRows {
			log.Printf("ERROR: Database error retrieving email verification for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}

		now := time.Now().UTC()

		// If it has been 10 minutes since the last attempt, clear attempt counter (forgiveness)
		if emailVerification.LastAttempt != nil && now.Sub(*emailVerification.LastAttempt) > 10*time.Minute {
			log.Printf("Email %s: Clearing token_count due to 10-minute forgiveness.", req.Email)
			emailVerification.TokenCount = 0 // Reset for the current check
			_, err = db.Exec(ctx, "UPDATE email_verifications SET token_count = 0 WHERE email = $1", req.Email)
			if err != nil {
				log.Printf("ERROR: Failed to reset token_count for %s: %v", req.Email, err)
				// Don't block, just log and continue
			}
		}

		rateLimitPerHour, _ := strconv.Atoi(getSetting("rate_limit_tokens_per_hour", "10"))
		if emailVerification.TokenCount >= rateLimitPerHour {
			log.Printf("Email %s: Rate limit exceeded (%d attempts).", req.Email, emailVerification.TokenCount)
			_, err = db.Exec(ctx,
				`UPDATE email_verifications SET last_blocked = $1, blocked_count = blocked_count + 1 WHERE email = $2`,
				now, req.Email,
			)
			if err != nil {
				log.Printf("ERROR: Failed to update last_blocked for %s: %v", req.Email, err)
			}
			c.JSON(429, gin.H{"error": "Email rate limit exceeded"})
			return
		}


		// Generate new FIRM token
		firmToken := GenerateFIRMToken()
		expiresAt := now.Add(60 * time.Minute) // FIRM token expires in 60 minutes

		// Insert FIRM token into tokens table
		_, err = db.Exec(ctx,
			`INSERT INTO tokens (token_id, email, created_at, expires_at, status) VALUES ($1, $2, $3, $4, $5)`,
			firmToken, req.Email, now, expiresAt, "issued",
		)
		if err != nil {
			log.Printf("ERROR: Failed to insert FIRM token for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Failed to create verification token"})
			return
		}

		// UPSERT into email_verifications
		ipHex, _ := IPNormalization(c.ClientIP()) // IPNormalization should not error here as it's checked by middleware
		_, err = db.Exec(ctx,
			`INSERT INTO email_verifications (email, first_seen, token_count, last_token, last_ip, last_attempt, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (email) DO UPDATE SET
                 token_count = email_verifications.token_count + 1,
                 last_token = EXCLUDED.last_token,
                 last_ip = EXCLUDED.last_ip,
                 last_attempt = EXCLUDED.last_attempt,
                 expires_at = $7;`, // Expires 1 day from now, or updated.
			req.Email, now, emailVerification.TokenCount+1, firmToken, ipHex, now, now.Add(24*time.Hour),
		)
		if err != nil {
			log.Printf("ERROR: Failed to upsert email_verifications for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Failed to update email verification record"})
			return
		}

		// Update ip_activity: token_requests count
		_, err = db.Exec(ctx,
			`INSERT INTO ip_activity (ip_hex, first_seen, last_seen, token_requests, expires_at)
             VALUES ($1, $2, $3, 1, $4)
             ON CONFLICT (ip_hex) DO UPDATE SET
                 last_seen = EXCLUDED.last_seen,
                 token_requests = ip_activity.token_requests + 1,
                 expires_at = $4;`,
			ipHex, now, now, now.Add(24*time.Hour),
		)
		if err != nil {
			log.Printf("ERROR: Failed to update ip_activity token_requests for %s: %v", ipHex, err)
			// Don't block, just log and continue
		}

		c.JSON(202, gin.H{
			"message": fmt.Sprintf("Send an email from %s to %s with token %s in the subject or body.", req.Email, firmServerEmail, firmToken),
			"token":   firmToken,
		})
	})


	// ✅ /inbound route (POST: {from, subject, body, headers})
	r.POST("/inbound", func(c *gin.Context) {
		var req struct {
			Email   string `json:"email" binding:"required,email"` // This is MAIL FROM
			Subject string `json:"subject"`
			Body    string `json:"body"`
			Headers map[string]string `json:"headers"` // Map of headers including "From"
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		if IsBlockedIP(c) {
			c.JSON(403, gin.H{"error": "IP blocked"})
			return
		}

		// Email rate limiting
		var emailVerification struct {
			TokenCount  int       `db:"token_count"`
			LastAttempt *time.Time `db:"last_attempt"`
			LastBlocked *time.Time `db:"last_blocked"`
		}
		err := db.QueryRow(ctx, "SELECT token_count, last_attempt, last_blocked FROM email_verifications WHERE email = $1", req.Email).Scan(
			&emailVerification.TokenCount, &emailVerification.LastAttempt, &emailVerification.LastBlocked,
		)
		if err != nil && err != pgx.ErrNoRows {
			log.Printf("ERROR: Database error retrieving email verification for inbound %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}

		now := time.Now().UTC()
		if emailVerification.LastAttempt != nil && now.Sub(*emailVerification.LastAttempt) > 10*time.Minute {
			log.Printf("Email %s (inbound): Clearing token_count due to 10-minute forgiveness.", req.Email)
			emailVerification.TokenCount = 0
			_, err = db.Exec(ctx, "UPDATE email_verifications SET token_count = 0 WHERE email = $1", req.Email)
			if err != nil {
				log.Printf("ERROR: Failed to reset token_count for inbound %s: %v", req.Email, err)
			}
		}

		rateLimitPerHour, _ := strconv.Atoi(getSetting("rate_limit_tokens_per_hour", "10"))
		if emailVerification.TokenCount >= rateLimitPerHour {
			log.Printf("Email %s (inbound): Rate limit exceeded (%d attempts).", req.Email, emailVerification.TokenCount)
			_, err = db.Exec(ctx,
				`UPDATE email_verifications SET last_blocked = $1, blocked_count = blocked_count + 1 WHERE email = $2`,
				now, req.Email,
			)
			if err != nil {
				log.Printf("ERROR: Failed to update last_blocked for inbound %s: %v", req.Email, err)
			}
			c.JSON(429, gin.H{"error": "Email rate limit exceeded"})
			return
		}


		// Draft Section 7.1: Inbound Mail Authentication
		if !verifySPF(req.Email, c.ClientIP()) {
			c.JSON(403, gin.H{"error": "SPF check failed. See https://firm.example.com/blog/spf-dkim"})
			return
		}
		if !verifyDKIM(req.Headers) {
			c.JSON(403, gin.H{"error": "DKIM check failed. See https://firm.example.com/blog/spf-dkim"})
			return
		}

		mailFromDomain := strings.ToLower(strings.Split(req.Email, "@")[1])
		fromHeader, ok := req.Headers["From"] // Get "From" header from the map
		if !ok || fromHeader == "" {
			c.JSON(403, gin.H{"error": "Missing 'From' header for domain matching"})
			return
		}
		fromHeaderParts := strings.Split(fromHeader, "@")
		if len(fromHeaderParts) < 2 {
			c.JSON(403, gin.H{"error": "Malformed 'From' header for domain matching"})
			return
		}
		fromHeaderDomain := strings.ToLower(fromHeaderParts[1])

		if mailFromDomain != fromHeaderDomain {
			c.JSON(403, gin.H{"error": "MAIL FROM and From header domains mismatch"})
			return
		}

		firmToken := ExtractFirstToken(req.Subject, req.Body)
		if firmToken == "" || !strings.HasPrefix(firmToken, "FIRM-TOKEN:") {
			c.JSON(400, gin.H{"error": "Invalid token"})
			return
		}

		// Lookup token:
		var tokenRecord struct {
			Email     string    `db:"email"`
			ExpiresAt time.Time `db:"expires_at"`
			Status    string    `db:"status"`
		}
		err = db.QueryRow(ctx, "SELECT email, expires_at, status FROM tokens WHERE token_id = $1", firmToken).Scan(
			&tokenRecord.Email, &tokenRecord.ExpiresAt, &tokenRecord.Status,
		)
		if err != nil {
			if err == pgx.ErrNoRows {
				c.JSON(404, gin.H{"error": "Token not found"})
				return
			}
			log.Printf("ERROR: Database error retrieving token %s: %v", firmToken, err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}

		if tokenRecord.Status != "issued" {
			c.JSON(400, gin.H{"error": "Token not usable"})
			return
		}
		if tokenRecord.ExpiresAt.Before(now) {
			c.JSON(400, gin.H{"error": "Token expired"})
			return
		}
		if tokenRecord.Email != req.Email {
			c.JSON(403, gin.H{"error": "Token does not belong to sender"})
			return
		}

		// Update token status to verified
		_, err = db.Exec(ctx, "UPDATE tokens SET status = 'verified', used_at = $1 WHERE token_id = $2", now, firmToken)
		if err != nil {
			log.Printf("ERROR: Failed to update token status for %s: %v", firmToken, err)
			c.JSON(500, gin.H{"error": "Failed to update token status"})
			return
		}

		// SET email_verifications.verified = TRUE
		_, err = db.Exec(ctx, "UPDATE email_verifications SET verified = TRUE, last_attempt = $1 WHERE email = $2", now, req.Email)
		if err != nil {
			log.Printf("ERROR: Failed to update email verification status for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Failed to update email verification status"})
			return
		}

		// Update ip_activity for inbound attempts
		ipHex, _ := IPNormalization(c.ClientIP())
		_, err = db.Exec(ctx,
			`INSERT INTO ip_activity (ip_hex, first_seen, last_seen, inbound_attempts, expires_at)
             VALUES ($1, $2, $3, 1, $4)
             ON CONFLICT (ip_hex) DO UPDATE SET
                 last_seen = EXCLUDED.last_seen,
                 inbound_attempts = ip_activity.inbound_attempts + 1,
                 expires_at = $4;`,
			ipHex, now, now, now.Add(24*time.Hour), // 1 day expiration
		)
		if err != nil {
			log.Printf("ERROR: Failed to update ip_activity inbound_attempts for %s: %v", ipHex, err)
			// Don't block, just log
		}

		// Determine scope (user or admin)
		var adminCount int
		err = db.QueryRow(ctx, "SELECT COUNT(*) FROM admin_emails WHERE email = $1", req.Email).Scan(&adminCount)
		if err != nil {
			log.Printf("ERROR: Database error checking admin status for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		scope := "user"
		if adminCount > 0 {
			scope = "admin"
		}

		// Generate JWT refresh token
		jwtRefreshToken, err := GenerateJWT(req.Email, scope)
		if err != nil {
			log.Printf("ERROR: Failed to generate JWT for %s: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Failed to issue JWT"})
			return
		}

		// Send welcome email (optional)
		sendWelcomeEmailSetting := getSetting("send_welcome_email", "true")
		if sendWelcomeEmailSetting == "true" {
			sendWelcomeEmail(req.Email) // Mocked
		}

		// Notify client via WebSocket (mocked)
		sendWebSocketEvent("verification_success", req.Email, jwtRefreshToken, now) // Mocked

		c.JSON(200, gin.H{"message": "Verification successful", "refresh_token": jwtRefreshToken})
	})

	// ✅ POST /refresh
	r.POST("/refresh", func(c *gin.Context) {
		var req struct {
			Token string `json:"token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		claims, err := ValidateJWT(req.Token)
		if err != nil {
			c.JSON(401, gin.H{"error": fmt.Sprintf("Invalid or expired refresh token: %v", err)})
			return
		}

		// Revoke the old JWT
		err = RevokeJWT(claims.ID)
		if err != nil {
			log.Printf("ERROR: Failed to revoke old JWT %s during refresh: %v", claims.ID, err)
			c.JSON(500, gin.H{"error": "Failed to revoke old token"})
			return
		}

		// Issue a new JWT with the same subject and scope
		newJWT, err := GenerateJWT(claims.Email, claims.Scope)
		if err != nil {
			log.Printf("ERROR: Failed to generate new JWT for %s during refresh: %v", claims.Email, err)
			c.JSON(500, gin.H{"error": "Failed to issue new token"})
			return
		}

		c.JSON(200, gin.H{"refresh_token": newJWT})
	})

	// ✅ POST /revoke
	r.POST("/revoke", func(c *gin.Context) {
		var req struct {
			Token string `json:"token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		claims, err := ValidateJWT(req.Token)
		if err != nil {
			c.JSON(401, gin.H{"error": fmt.Sprintf("Invalid or expired token: %v", err)})
			return
		}

		err = RevokeJWT(claims.ID)
		if err != nil {
			log.Printf("ERROR: Failed to revoke JWT %s: %v", claims.ID, err)
			c.JSON(500, gin.H{"error": "Failed to revoke token"})
			return
		}

		c.JSON(200, gin.H{"message": "Token revoked"})
	})


	// ✅ POST /admin/bootstrap (email: STRING)
	// Localhost-only endpoint for adding an initial admin email.
	// This endpoint is outside the adminGroup to bypass JWT auth.
	r.POST("/admin/bootstrap", func(c *gin.Context) {
		// This endpoint MUST be restricted to localhost (127.0.0.1 or ::1)
		if c.ClientIP() != "127.0.0.1" && c.ClientIP() != "::1" { // Check for IPv4 and IPv6 localhost
			c.JSON(403, gin.H{"error": "Localhost only"})
			return
		}

		var req struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		now := time.Now().UTC()

		// UPSERT into admin_emails
		_, err = db.Exec(ctx,
			`INSERT INTO admin_emails (email, added_at, added_by, notes)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (email) DO UPDATE SET
                     added_at = EXCLUDED.added_at,
                     added_by = EXCLUDED.added_by,
                     notes = EXCLUDED.notes;`,
				req.Email, now, "bootstrap", "Added via localhost",
		)
		if err != nil {
			log.Printf("ERROR: Failed to add/update admin email %s via bootstrap: %v", req.Email, err)
			c.JSON(500, gin.H{"error": "Failed to add admin email"})
			return
		}

		// Log to admin_events
		_, err = db.Exec(ctx,
			"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
			now, "add_admin", "bootstrap", req.Email, "Added via localhost bootstrap.",
		)
		if err != nil {
			log.Printf("ERROR: Failed to log admin event for bootstrap: %v", err)
		}
		c.JSON(200, gin.H{"message": "Admin email added"})
	})


	// Admin UI Routes (these serve HTML templates)
	adminUIGroup := r.Group("/admin")
	{
		// Dashboard UI - Fetches data server-side
		adminUIGroup.GET("/dashboard", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			var totalVerifiedEmails int
			_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM email_verifications WHERE verified = TRUE").Scan(&totalVerifiedEmails)

			var activeJWTs int
			_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM tokens WHERE status = 'issued' AND expires_at > NOW()").Scan(&activeJWTs)

			var blockedIPsToday int
			today := time.Now().UTC().Truncate(24 * time.Hour)
			_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM ip_activity WHERE blocked = TRUE AND last_blocked >= $1", today).Scan(&blockedIPsToday)


			var recentAdminEvents []gin.H = make([]gin.H, 0) // Ensure empty slice for JSON array
			rows, err := db.Query(ctx, "SELECT timestamp, action, actor, target, notes FROM admin_events ORDER BY timestamp DESC LIMIT 10")
			if err == nil { // Only process if query was successful
				defer rows.Close()
				for rows.Next() {
					var ts time.Time
					var action, actor string
					var target, notes *string // Use pointers for nullable text fields
					if err := rows.Scan(&ts, &action, &actor, &target, &notes); err == nil {
						event := gin.H{
							"Timestamp": ts.Format("2006-01-02 15:04:05 UTC"),
							"Action":    action,
							"Actor":     actor,
							"Target":    "",
							"Notes":     "",
						}
						if target != nil { event["Target"] = *target }
						if notes != nil { event["Notes"] = *notes }
						recentAdminEvents = append(recentAdminEvents, event)
					}
				}
			} else {
				log.Printf("ERROR: Failed to query recent admin events for dashboard UI: %v", err)
			}


			// Render the layout template, passing a dictionary with the content template name
			c.HTML(200, "layout.html", gin.H{ // Changed to "layout.html"
				"Title":   "Dashboard",
				"ContentTemplate": "admin/dashboard.html", // Key to indicate which content template to render, now relative to templates/
				"Stats": gin.H{
					"TotalVerifiedEmails": totalVerifiedEmails,
					"ActiveJWTs":          activeJWTs,
					"BlockedIPsToday":     blockedIPsToday,
				},
				"RecentAdminEvents": recentAdminEvents,
			})
		})

		// Subnets UI - Fetches data server-side
		adminUIGroup.GET("/subnets_ui", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			rows, err := db.Query(ctx, "SELECT subnet_hex, cidr, reason, banned_at, expires_at, hits FROM banned_subnets ORDER BY banned_at DESC")
			if err != nil {
				log.Printf("ERROR: Failed to query banned subnets for UI: %v", err)
				c.JSON(500, gin.H{"error": "Failed to retrieve banned subnets for UI"})
				return
			}
			defer rows.Close()

			var subnets []gin.H = make([]gin.H, 0) // Initialize as empty, non-nil slice
			for rows.Next() {
				var subnetHex string
				var cidr, hits int
				var reason string
				var bannedAt time.Time
				var expiresAt *time.Time

				if err := rows.Scan(&subnetHex, &cidr, &reason, &bannedAt, &expiresAt, &hits); err != nil {
					log.Printf("ERROR: Failed to scan banned subnet row for UI: %v", err)
					continue
				}

				subnet := gin.H{
					"subnet_hex": subnetHex,
					"cidr":       cidr,
					"reason":     reason,
					"banned_at":  bannedAt.Format(time.RFC3339),
					"hits":       hits,
				}
				if expiresAt != nil {
					subnet["expires_at"] = expiresAt.Format(time.RFC3339)
				} else {
					subnet["expires_at"] = nil
				}
				subnets = append(subnets, subnet)
			}
			c.HTML(200, "layout.html", gin.H{ // Changed to "layout.html"
				"Title":           "Banned Subnets",
				"ContentTemplate": "admin/subnets.html", // Specify the content template name, now relative to templates/
				"Subnets": subnets,
			})
		})

		// Placeholder UI routes
		adminUIGroup.GET("/emails_ui", func(c *gin.Context) {
			c.HTML(200, "layout.html", gin.H{"Title": "Admin Emails", "ContentTemplate": "admin/emails.html"})
		})
		adminUIGroup.GET("/ip_ui", func(c *gin.Context) {
			c.HTML(200, "layout.html", gin.H{"Title": "IP Activity", "ContentTemplate": "admin/ip.html"})
		})
		adminUIGroup.GET("/settings_ui", func(c *gin.Context) {
			// Fetch all settings to pre-populate the form
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			rows, err := db.Query(ctx, "SELECT key, value, description FROM settings")
			if err != nil {
				log.Printf("ERROR: Failed to query settings for UI: %v", err)
				c.JSON(500, gin.H{"error": "Failed to retrieve settings for UI"})
				return
			}
			defer rows.Close()

			settings := make([]gin.H, 0)
			for rows.Next() {
				var key, value, description string
				if err := rows.Scan(&key, &value, &description); err != nil {
					log.Printf("ERROR: Failed to scan setting row for UI: %v", err)
					continue
				}
				settings = append(settings, gin.H{"Key": key, "Value": value, "Description": description})
			}

			c.HTML(200, "layout.html", gin.H{ // Changed to "layout.html"
				"Title":    "Settings",
				"ContentTemplate": "admin/settings.html", // Specify the content template name, now relative to templates/
				"Settings": settings,
			})
		})
		adminUIGroup.GET("/logs_ui", func(c *gin.Context) {
			c.HTML(200, "layout.html", gin.H{"Title": "Admin Logs", "ContentTemplate": "admin/logs.html"})
		})

		// Simple logout endpoint (placeholder for now)
		adminUIGroup.GET("/logout", func(c *gin.Context) {
			// In a real app, this would clear client-side token and perhaps server-side session.
			// For simplicity, we can just render a basic message and expect the client-side JS
			// to clear the token and redirect.
			c.String(200, "You have been logged out. Please clear your local storage.")
		})
	}


	// Admin API Endpoints (these ARE protected by JWT middleware and return JSON)
	adminApiGroup := r.Group("/admin/api") // NEW GROUP FOR JSON API CALLS
	{
		// Middleware to check admin JWT (APPLIED ONLY TO THIS GROUP)
		adminApiGroup.Use(func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(403, gin.H{"error": "Admin access required: Missing or invalid Authorization header"})
				c.Abort()
				return
			}
			jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := ValidateJWT(jwtToken)
			if err != nil {
				c.JSON(403, gin.H{"error": fmt.Sprintf("Admin access required: Invalid or expired JWT: %v", err)})
				c.Abort()
				return
			}

			if claims.Scope != "admin" {
				c.JSON(403, gin.H{"error": "Admin access required: Insufficient scope"})
				c.Abort()
				return
			}

			// Check if the admin email exists in the admin_emails table
			var count int
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = db.QueryRow(ctx, "SELECT COUNT(*) FROM admin_emails WHERE email = $1", claims.Email).Scan(&count)
			if err != nil || count == 0 {
				c.JSON(403, gin.H{"error": "Admin access required: Authenticated user is not an active admin"})
				c.Abort()
				return
			}

			c.Set("adminEmail", claims.Email) // Pass admin email to context
			c.Next()
		})

		// API endpoint to fetch dashboard stats
		adminApiGroup.GET("/dashboard_stats", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			var totalVerifiedEmails int
			// Handle potential error, though unlikely for COUNT(*)
			if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM email_verifications WHERE verified = TRUE").Scan(&totalVerifiedEmails); err != nil {
				log.Printf("ERROR: DB query for TotalVerifiedEmails: %v", err)
				c.JSON(500, gin.H{"error": "Failed to fetch total verified emails"})
				return
			}

			var activeJWTs int
			if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM tokens WHERE status = 'issued' AND expires_at > NOW()").Scan(&activeJWTs); err != nil {
				log.Printf("ERROR: DB query for ActiveJWTs: %v", err)
				c.JSON(500, gin.H{"error": "Failed to fetch active JWTs"})
				return
			}

			var blockedIPsToday int
			today := time.Now().UTC().Truncate(24 * time.Hour)
			if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM ip_activity WHERE blocked = TRUE AND last_blocked >= $1", today).Scan(&blockedIPsToday); err != nil {
				log.Printf("ERROR: DB query for BlockedIPsToday: %v", err)
				c.JSON(500, gin.H{"error": "Failed to fetch blocked IPs today"})
				return
			}

			var recentAdminEvents []gin.H = make([]gin.H, 0)
			rows, err := db.Query(ctx, "SELECT timestamp, action, actor, target, notes FROM admin_events ORDER BY timestamp DESC LIMIT 10")
			if err != nil {
				log.Printf("ERROR: Failed to query recent admin events for API: %v", err)
				// Don't return 500, just log and send partial data
			} else {
				defer rows.Close()
				for rows.Next() {
					var ts time.Time
					var action, actor string
					var target, notes *string
					if err := rows.Scan(&ts, &action, &actor, &target, &notes); err != nil {
						log.Printf("ERROR: Failed to scan admin event row for API: %v", err)
						continue
					}
					event := gin.H{
						"Timestamp": ts.Format("2006-01-02 15:04:05 UTC"),
						"Action":    action,
						"Actor":     actor,
						"Target":    "",
						"Notes":     "",
					}
					if target != nil { event["Target"] = *target }
					if notes != nil { event["Notes"] = *notes }
					recentAdminEvents = append(recentAdminEvents, event)
				}
			}

			c.JSON(200, gin.H{
				"TotalVerifiedEmails": totalVerifiedEmails,
				"ActiveJWTs":          activeJWTs,
				"BlockedIPsToday":     blockedIPsToday,
				"RecentAdminEvents":   recentAdminEvents,
			})
		})

		// ✅ GET /admin/api/subnets (API endpoint, now under adminApiGroup)
		adminApiGroup.GET("/subnets", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			rows, err := db.Query(ctx, "SELECT subnet_hex, cidr, reason, banned_at, expires_at, hits FROM banned_subnets ORDER BY banned_at DESC")
			if err != nil {
				log.Printf("ERROR: Failed to query banned subnets API: %v", err)
				c.JSON(500, gin.H{"error": "Failed to retrieve banned subnets API"})
				return
			}
			defer rows.Close()

			var subnets []gin.H = make([]gin.H, 0) // Ensure empty slice for JSON array
			for rows.Next() {
				var subnetHex string
				var cidr, hits int
				var reason string
				var bannedAt time.Time
				var expiresAt *time.Time

				if err := rows.Scan(&subnetHex, &cidr, &reason, &bannedAt, &expiresAt, &hits); err != nil {
					log.Printf("ERROR: Failed to scan banned subnet API row: %v", err)
					continue
				}

				subnet := gin.H{
					"subnet_hex": subnetHex,
					"cidr":       cidr,
					"reason":     reason,
					"banned_at":  bannedAt.Format(time.RFC3339),
					"hits":       hits,
				}
				if expiresAt != nil {
					subnet["expires_at"] = expiresAt.Format(time.RFC3339)
				} else {
					subnet["expires_at"] = nil
				}
				subnets = append(subnets, subnet)
			}
			c.JSON(200, subnets)
		})

		// ✅ POST /admin/api/subnet (API endpoint)
		adminApiGroup.POST("/subnet", func(c *gin.Context) {
			var req struct {
				Subnet        string `json:"subnet" binding:"required"`
				CIDR          int    `json:"cidr" binding:"required"`
				Action        string `json:"action" binding:"required"` // "add" or "delete"
				Reason        string `json:"reason"`
				ExpiresInDays *int   `json:"expires_in_days"` // Optional, pointer for nullability
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}

			adminEmail := c.GetString("adminEmail") // Set by admin middleware

			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			subnetHex, err := NormalizeCIDR(req.Subnet, req.CIDR)
			if err != nil {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid subnet or CIDR: %v", err)})
				return
			}

			now := time.Now().UTC()
			var expiresAt *time.Time
			if req.ExpiresInDays != nil {
				exp := now.Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
				expiresAt = &exp
			}

			var cmdTag pgconn.CommandTag // Declared here once
			// err is already declared by c.ShouldBindJSON, so use assignment
			if req.Action == "add" {
				cmdTag, err = db.Exec(ctx, // Now it's an assignment
					`INSERT INTO banned_subnets (subnet_hex, cidr, reason, banned_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (subnet_hex, cidr) DO UPDATE SET
                         reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at, expires_at = EXCLUDED.expires_at, hits = banned_subnets.hits + 1;`,
					subnetHex, req.CIDR, req.Reason, now, expiresAt,
				)
				if err != nil {
					log.Printf("ERROR: Failed to add/update banned subnet %s/%d: %v", req.Subnet, req.CIDR, err)
					c.JSON(500, gin.H{"error": "Failed to add/update subnet"})
					return
				}
				if cmdTag.RowsAffected() == 0 {
					log.Printf("WARN: Add/update subnet %s/%d resulted in no rows affected.", req.Subnet, req.CIDR)
				}
			} else if req.Action == "delete" {
				cmdTag, err = db.Exec(ctx, "DELETE FROM banned_subnets WHERE subnet_hex = $1 AND cidr = $2", subnetHex, req.CIDR) // Assignment
				if err != nil {
					log.Printf("ERROR: Failed to delete banned subnet %s/%d: %v", req.Subnet, req.CIDR, err)
					c.JSON(500, gin.H{"error": "Failed to delete subnet"})
					return
				}
				if cmdTag.RowsAffected() == 0 {
					c.JSON(404, gin.H{"error": "Subnet not found for deletion"})
					return
				}
			} else {
				c.JSON(400, gin.H{"error": "Invalid action. Must be 'add' or 'delete'."})
				return
			}

			// Log to admin_events
			_, err = db.Exec(ctx,
				"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
				now, fmt.Sprintf("%s_subnet", req.Action), adminEmail, fmt.Sprintf("%s/%d", subnetHex, req.CIDR), req.Reason,
			)
			if err != nil {
				log.Printf("ERROR: Failed to log admin event for subnet management: %v", err)
			}
			c.JSON(200, gin.H{"message": fmt.Sprintf("Subnet %s", req.Action)})
		})

		// ✅ GET /admin/api/ip/:ipaddress (API endpoint)
		adminApiGroup.GET("/ip/:ipaddress", func(c *gin.Context) {
			ipStr := c.Param("ipaddress")
			ipHex, err := IPNormalization(ipStr)
			if err != nil {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid IP address format: %v", err)})
				return
			}

			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			var ipActivity struct {
				IPHex           string    `db:"ip_hex"`
				FirstSeen       time.Time `db:"first_seen"`
				LastSeen        *time.Time `db:"last_seen"`
				TokenRequests   int       `db:"token_requests"`
				InboundAttempts int       `db:"inbound_attempts"`
				Blocked         bool      `db:"blocked"`
				BlockedCount    int       `db:"blocked_count"`
				LastBlocked     *time.Time `db:"last_blocked"`
				ExpiresAt       *time.Time `db:"expires_at"`
				Notes           *string   `db:"notes"`
			}
			err = db.QueryRow(ctx, `
				SELECT ip_hex, first_seen, last_seen, token_requests, inbound_attempts, blocked, blocked_count, last_blocked, expires_at, notes
				FROM ip_activity WHERE ip_hex = $1`, ipHex).Scan(
				&ipActivity.IPHex, &ipActivity.FirstSeen, &ipActivity.LastSeen, &ipActivity.TokenRequests,
				&ipActivity.InboundAttempts, &ipActivity.Blocked, &ipActivity.BlockedCount, &ipActivity.LastBlocked,
				&ipActivity.ExpiresAt, &ipActivity.Notes,
			)

			if err != nil {
				if err == pgx.ErrNoRows {
					c.JSON(404, gin.H{"error": "IP activity record not found"})
					return
				}
				log.Printf("ERROR: Failed to query IP activity for %s: %v", ipHex, err)
				c.JSON(500, gin.H{"error": "Failed to retrieve IP activity"})
				return
			}

			// Check if this IP falls into any currently banned subnets
			var isBlockedBySubnet bool
			rows, err := db.Query(ctx, "SELECT subnet_hex, cidr FROM banned_subnets")
			if err == nil {
				defer rows.Close()
				ipNet := net.ParseIP(ipStr)
				for rows.Next() {
					var sHex string
					var sCidr int
					if rows.Scan(&sHex, &sCidr) == nil {
						// Convert hex back to IP for net.ParseCIDR
						// This is a simplified conversion, actual implementation might need more care
						var parsedIP net.IP
						if len(sHex) == 8 { // IPv4
							b, _ := strconv.ParseUint(sHex, 16, 32)
							parsedIP = net.IPv4(byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
						} else if len(sHex) == 32 { // IPv6
							// Correct parsing for IPv6 hex to byte array
							parsedIP = make(net.IP, net.IPv6len)
							_, err := fmt.Sscanf(sHex, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
								&parsedIP[0], &parsedIP[1], &parsedIP[2], &parsedIP[3], &parsedIP[4], &parsedIP[5], &parsedIP[6], &parsedIP[7],
								&parsedIP[8], &parsedIP[9], &parsedIP[10], &parsedIP[11], &parsedIP[12], &parsedIP[13], &parsedIP[14], &parsedIP[15])
							if err != nil {
								log.Printf("WARNING: Failed to parse IPv6 hex %s for subnet check: %v", sHex, err)
								continue
							}
						} else {
							continue // Unknown hex length
						}
						// Ensure parsedIP is not nil before using
						if parsedIP != nil {
							_, subnetNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", parsedIP.String(), sCidr))
							if err == nil && subnetNet.Contains(ipNet) {
								isBlockedBySubnet = true
								break
							}
						}
					}
				}
			}


			c.JSON(200, gin.H{
				"ip_address":        ipStr,
				"ip_hex":            ipActivity.IPHex,
				"first_seen":        ipActivity.FirstSeen.Format(time.RFC3339),
				"last_seen":         ipActivity.LastSeen.Format(time.RFC3339),
				"token_requests":    ipActivity.TokenRequests,
				"inbound_attempts":  ipActivity.InboundAttempts,
				"blocked_by_status": ipActivity.Blocked,
				"blocked_count":     ipActivity.BlockedCount,
				"last_blocked":      ipActivity.LastBlocked.Format(time.RFC3339),
				"expires_at":        ipActivity.ExpiresAt.Format(time.RFC3339),
				"notes":             ipActivity.Notes,
				"is_blocked_by_subnet": isBlockedBySubnet, // Additional info
			})
		})

		// ✅ GET /admin/api/emails (API endpoint)
		adminApiGroup.GET("/emails", func(c *gin.Context) {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			rows, err := db.Query(ctx, "SELECT email, added_at, added_by, expires_at, notes FROM admin_emails ORDER BY added_at DESC")
			if err != nil {
				log.Printf("ERROR: Failed to query admin emails API: %v", err)
				c.JSON(500, gin.H{"error": "Failed to retrieve admin emails API"})
				return
			}
			defer rows.Close()

			var adminEmails []gin.H = make([]gin.H, 0) // Initialize as empty, non-nil slice
			for rows.Next() {
				var email, addedBy string
				var addedAt time.Time
				var expiresAt *time.Time
				var notes *string

				if err := rows.Scan(&email, &addedAt, &addedBy, &expiresAt, &notes); err != nil {
					log.Printf("ERROR: Failed to scan admin email API row: %v", err)
					continue
				}

				adminEmailEntry := gin.H{
					"email":      email,
					"added_at":   addedAt.Format(time.RFC3339),
					"added_by":   addedBy,
					"expires_at": nil,
					"notes":      nil,
				}
				if expiresAt != nil {
					adminEmailEntry["expires_at"] = expiresAt.Format(time.RFC3339)
				}
				if notes != nil {
					adminEmailEntry["notes"] = *notes
				}
				adminEmails = append(adminEmails, adminEmailEntry)
			}
			c.JSON(200, adminEmails)
		})

		// ✅ POST /admin/api/email (API endpoint)
		adminApiGroup.POST("/email", func(c *gin.Context) {
			var req struct {
				Email      string `json:"email" binding:"required,email"`
				Action     string `json:"action" binding:"required"` // "add" or "delete"
				Notes      string `json:"notes"`
				ExpiresInDays *int `json:"expires_in_days"` // Optional for "add"
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}

			adminEmail := c.GetString("adminEmail") // Set by admin middleware

			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			now := time.Now().UTC()
			var expiresAt *time.Time
			if req.ExpiresInDays != nil {
				exp := now.Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
				expiresAt = &exp
			}

			var cmdTag pgconn.CommandTag // Declared here once
			// err is already declared by c.ShouldBindJSON, so use assignment
			if req.Action == "add" {
				cmdTag, err = db.Exec(ctx, // Now it's an assignment
					`INSERT INTO admin_emails (email, added_at, added_by, expires_at, notes)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (email) DO UPDATE SET
                         added_at = EXCLUDED.added_at, added_by = EXCLUDED.added_by,
                         expires_at = EXCLUDED.expires_at, notes = EXCLUDED.notes;`,
					req.Email, now, adminEmail, expiresAt, req.Notes,
				)
				if err != nil {
					log.Printf("ERROR: Failed to add/update admin email %s: %v", req.Email, err)
					c.JSON(500, gin.H{"error": "Failed to add/update admin email"})
					return
				}
			} else if req.Action == "delete" {
				cmdTag, err = db.Exec(ctx, "DELETE FROM admin_emails WHERE email = $1", req.Email) // Assignment
				if err != nil {
					log.Printf("ERROR: Failed to delete admin email %s: %v", req.Email, err)
					c.JSON(500, gin.H{"error": "Failed to delete admin email"})
					return
				}
				if cmdTag.RowsAffected() == 0 {
					c.JSON(404, gin.H{"error": "Admin email not found for deletion"})
					return
				}
			} else {
				c.JSON(400, gin.H{"error": "Invalid action. Must be 'add' or 'delete'."})
				return
			}

			// Log to admin_events
			_, err = db.Exec(ctx,
				"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
				now, fmt.Sprintf("%s_admin_email", req.Action), adminEmail, req.Email, req.Notes,
			)
			if err != nil {
				log.Printf("ERROR: Failed to log admin event for email management: %v", err)
			}
			c.JSON(200, gin.H{"message": fmt.Sprintf("Admin email %s", req.Action)})
		})

		// ✅ POST /admin/api/settings (API endpoint)
		adminApiGroup.POST("/settings", func(c *gin.Context) {
			var req struct {
				Key   string `json:"key" binding:"required"`
				Value string `json:"value" binding:"required"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}

			adminEmail := c.GetString("adminEmail")

			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			// Validate specific settings
			switch req.Key {
			case "rate_limit_tokens_per_hour":
				val, err := strconv.Atoi(req.Value)
				if err != nil || val <= 0 {
					c.JSON(400, gin.H{"error": "Rate limit must be a positive integer"})
					return
				}
			case "email_retention_period":
				_, err := time.ParseDuration(req.Value)
				if err != nil {
					c.JSON(400, gin.H{"error": "Invalid duration format (e.g., 365d, 1y)"})
					return
				}
			case "cleanup_interval":
				duration, err := time.ParseDuration(req.Value)
				if err != nil || duration < 5*time.Second || duration > 60*time.Second {
					c.JSON(400, gin.H{"error": "Cleanup interval must be 5s-60s"})
					return
				}
			case "send_welcome_email":
				if req.Value != "true" && req.Value != "false" {
					c.JSON(400, gin.H{"error": "send_welcome_email must be 'true' or 'false'"})
					return
				}
			case "firm_server_email":
				if !strings.Contains(req.Value, "@") { // Basic email format check
					c.JSON(400, gin.H{"error": "firm_server_email must be a valid email address"})
					return
				}
				firmServerEmail = req.Value // Update global variable immediately
			case "jwt_secret_key":
				if len(req.Value) < 32 { // Arbitrary minimum length for security
					c.JSON(400, gin.H{"error": "JWT secret key must be at least 32 characters long"})
					return
				}
				jwtSecretKey = []byte(req.Value) // Update global variable immediately
			case "imap_server", "imap_username", "imap_password":
				if req.Value == "" {
					c.JSON(400, gin.H{"error": fmt.Sprintf("%s cannot be empty", req.Key)})
					return
				}
			case "imap_polling_interval":
				val, err := strconv.Atoi(req.Value)
				if err != nil || val < 1 || val > 30 {
					c.JSON(400, gin.H{"error": "Polling interval must be 1-30 seconds"})
					return
				}
			case "imap_idle_enabled":
				if req.Value != "true" && req.Value != "false" {
					c.JSON(400, gin.H{"error": "IMAP IDLE must be 'true' or 'false'"})
					return
				}
			default:
				// Allow other settings to be stored without specific validation
			}

			err = updateSettingInDB(ctx, req.Key, req.Value, adminEmail)
			if err != nil {
				log.Printf("ERROR: Failed to update setting %s: %v", req.Key, err)
				c.JSON(500, gin.H{"error": "Failed to update setting"})
				return
			}

			// Log to admin_events
			_, err = db.Exec(ctx,
				"INSERT INTO admin_events (timestamp, action, actor, target, notes) VALUES ($1, $2, $3, $4, $5)",
				time.Now().UTC(), "update_setting", adminEmail, req.Key, req.Value,
			)
			if err != nil {
				log.Printf("ERROR: Failed to log admin event for settings update: %v", err)
			}
			c.JSON(200, gin.H{"message": "Setting updated"})
		})
	}


	// Run the server
	// Fixed: Use 8092 as the default port as requested
	port := os.Getenv("PORT")
	if port == "" {
		port = "8092" // Default port changed to 8092
	}
	log.Printf("Starting FIRM server on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("FATAL: Failed to start server: %v", err)
	}
}

