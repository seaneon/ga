package db

import (
    "database/sql"
    "fmt"

    "github.com/spf13/viper"
    _ "github.com/lib/pq"
)

// ConnectDB opens a connection to PostgreSQL using .env variables.
func ConnectDB() (*sql.DB, error) {
    connStr := fmt.Sprintf(
        "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
        viper.GetString("PG_HOST"),
        viper.GetString("PG_PORT"),
        viper.GetString("PG_USER"),
        viper.GetString("PG_PASSWORD"),
        viper.GetString("PG_DB"),
    )
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    return db, nil
}